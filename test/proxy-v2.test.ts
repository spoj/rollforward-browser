import { test } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { once } from 'node:events'
import fs from 'node:fs'
import http from 'node:http'
import net from 'node:net'
import os from 'node:os'
import tls from 'node:tls'
import { BrowserSession } from '../src/browser.ts'
import { loadBlocklists } from '../src/blocklists.ts'
import {
  ByteBudget,
  startProxy,
  type LogRecord,
  type ProxyV2Options,
  type Site,
  type V2Entry,
} from '../src/proxy.ts'
import { SecretVault } from '../src/redact.ts'

const pem = execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=test', '-keyout', '-', '-out', '-'], { stdio: ['ignore', 'pipe', 'ignore'] }).toString()
const tlsKey = { key: pem.slice(0, pem.indexOf('-----BEGIN CERTIFICATE')), cert: pem.slice(pem.indexOf('-----BEGIN CERTIFICATE')) }

async function setupHarness(t: any, proxyOpts?: ProxyV2Options, siteOverrides?: Partial<Site>) {
  const upstreamHits: Array<{ method: string; url: string; headers: http.IncomingHttpHeaders; body: Buffer }> = []
  let upstreamHandler: ((req: http.IncomingMessage, res: http.ServerResponse, body: Buffer) => void) | undefined
  const upstream = http.createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', c => chunks.push(c))
    req.on('end', () => {
      const body = Buffer.concat(chunks)
      upstreamHits.push({ method: req.method!, url: req.url!, headers: req.headers, body })
      if (upstreamHandler) return upstreamHandler(req, res, body)
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ ok: true, len: body.length }))
    })
  })
  upstream.on('upgrade', (req, socket) => {
    upstreamHits.push({ method: req.method!, url: req.url!, headers: req.headers, body: Buffer.alloc(0) })
    const accept = crypto.createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: upgrade\r\nsec-websocket-accept: ${accept}\r\n\r\n`)
    socket.end()
  })
  upstream.listen(0, '127.0.0.1')
  await once(upstream, 'listening')
  const upPort = (upstream.address() as net.AddressInfo).port

  const viaProxy = http.createServer()
  viaProxy.on('connect', (_req, socket, head) => {
    const target = net.connect(upPort, '127.0.0.1', () => {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
      target.write(head)
      socket.pipe(target).pipe(socket)
    })
    socket.on('error', () => target.destroy())
    target.on('error', () => socket.destroy())
  })
  viaProxy.listen(0, '127.0.0.1')
  await once(viaProxy, 'listening')
  const viaPort = (viaProxy.address() as net.AddressInfo).port

  const dir = fs.mkdtempSync(`${os.tmpdir()}/rf-proxy-v2-`)
  const sockPath = `${dir}/proxy.sock`
  const log: LogRecord[] = []
  const site: Site = {
    hosts: ['t.example'],
    via: { url: `http://127.0.0.1:${viaPort}`, token: 'via-tok', hosts: ['t.example'] },
    ...siteOverrides,
  }
  const proxy = startProxy(sockPath, site, tlsKey, () => false, log, undefined, undefined, {
    auditV2: { v: 2 },
    siteName: 'erp',
    ...proxyOpts,
  })
  await once(proxy, 'listening')

  t.after(() => {
    proxy.close()
    proxy.closeAllConnections()
    viaProxy.close()
    viaProxy.closeAllConnections()
    upstream.close()
    upstream.closeAllConnections()
    fs.rmSync(dir, { recursive: true, force: true })
  })

  const sendReq = (method: string, path: string, headers: Record<string, string> = {}, body?: Buffer | string, host = 't.example') =>
    new Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }>((resolve, reject) => {
      const req = http.request({
        socketPath: sockPath,
        method,
        path: `http://${host}:${upPort}${path}`,
        headers: { host: `${host}:${upPort}`, ...headers },
      }, res => {
        const chunks: Buffer[] = []
        res.on('data', c => chunks.push(c))
        res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body: Buffer.concat(chunks).toString() }))
      })
      req.on('error', reject)
      if (body !== undefined) req.end(body)
      else req.end()
    })

  return {
    sockPath,
    upPort,
    viaPort,
    site,
    log,
    proxy,
    upstreamHits,
    sendReq,
    setHandler: (fn: typeof upstreamHandler) => { upstreamHandler = fn },
  }
}

test('method override escalation only: POST+Override:GET stays write; override or body on safe verb forces isWrite', async t => {
  const { sendReq, log } = await setupHarness(t)

  await sendReq('POST', '/a', { 'x-http-method-override': 'GET', 'content-type': 'application/json' }, '{"x":1}')
  await sendReq('GET', '/b', { 'x-http-method-override': 'delete' })
  await sendReq('GET', '/c', { 'x-http-method-override': 'GET, DELETE' })
  await sendReq('GET', '/d', { 'x-http-method-override': 'bad!verb' })
  await sendReq('OPTIONS', '/e', { 'content-type': 'application/json', 'content-length': '7' }, '{"a":1}')

  const entries = log.filter((e): e is V2Entry => !e.rec)
  assert.equal(entries.length, 5)
  assert.equal(entries[0].isWrite, true)
  assert.equal(entries[0].effectiveMethod, 'POST')
  assert.equal(entries[1].isWrite, true)
  assert.equal(entries[1].effectiveMethod, 'DELETE')
  assert.equal(entries[2].isWrite, true)
  assert.equal(entries[3].isWrite, true)
  assert.equal(entries[4].isWrite, true)
})

test('Expect: 100-continue forwards body and strips expect upstream; unsupported Expect returns 417 without reaching upstream', async t => {
  const { sendReq, upstreamHits, log } = await setupHarness(t)

  const r1 = await sendReq('POST', '/continue', { expect: '100-continue', 'content-type': 'application/json' }, '{"hello":"world"}')
  assert.equal(r1.status, 200)
  assert.equal(upstreamHits.length, 1)
  assert.equal(upstreamHits[0].headers['expect'], undefined)
  assert.equal(upstreamHits[0].body.toString(), '{"hello":"world"}')

  const r2 = await sendReq('POST', '/bad-expect', { expect: '999-unknown' }, 'abc')
  assert.equal(r2.status, 417)
  assert.equal(upstreamHits.length, 1)
  assert.ok(log.some(e => !e.rec && e.status === 417 && e.blocked === 'expectation failed'))
})

test('long-lived stream emits immutable incomplete entry at streamTimeoutMs and separate http_end on completion', async t => {
  const { sendReq, setHandler, log } = await setupHarness(t, { streamTimeoutMs: 60 })
  setHandler((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' })
    res.write('data: hello\n\n')
    setTimeout(() => res.end('data: bye\n\n'), 160)
  })
  const r = await sendReq('GET', '/events')
  assert.equal(r.status, 200)
  const first = log.find((e): e is V2Entry => !e.rec && e.incomplete === true)
  const late = log.find(e => e.rec === 'http_end')
  assert.ok(first)
  assert.ok(late && late.ref === first.n && (late.resBytes ?? 0) > 0)
})

test('log-full 403 refusal is scoped strictly to writes to site.hosts; non-site writes count-and-drop and non-write upgrades pass', async t => {
  const { sendReq, sockPath, upPort, log, proxy, site } = await setupHarness(t, { maxLogBytes: 14 * 1024 })
  // Allow other.example through via too, while NOT in site.hosts (simulating an open/telemetry host)
  site.via!.hosts.push('cdn.example')

  // Fill the log with site.hosts writes until the next site.hosts write gets 403 audit log full
  let got403 = false
  for (let i = 0; i < 40; i++) {
    const r = await sendReq('POST', `/write/${i}`, { 'content-type': 'application/json' }, JSON.stringify({ n: i }))
    if (r.status === 403 && r.body.includes('audit log full')) {
      got403 = true
      break
    }
  }
  assert.equal(got403, true, 'write to site.hosts refused 403 audit log full')

  // Non-write WebSocket upgrade MUST still succeed (101) when log is full
  const wsRes = await new Promise<string>(resolve => {
    const s = net.connect(sockPath)
    s.write(`GET http://t.example:${upPort}/ws HTTP/1.1\r\nhost: t.example:${upPort}\r\nupgrade: websocket\r\nconnection: upgrade\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n\r\n`)
    const chunks: Buffer[] = []
    s.on('data', c => chunks.push(c))
    s.on('end', () => resolve(Buffer.concat(chunks).toString()))
  })
  assert.match(wsRes, /^HTTP\/1\.1 101/, 'non-write upgrade passes even when log is full')

  // Non-site-host write in an open session is NOT refused 403 when log is full; it dispatches and counts as dropped
  const blSrv = http.createServer((_req, res) => res.end('evil.example\n')).listen(0, '127.0.0.1')
  await once(blSrv, 'listening')
  t.after(() => blSrv.close())
  const prevBl = process.env.BROWSER_BLOCKLISTS
  process.env.BROWSER_BLOCKLISTS = `http://127.0.0.1:${(blSrv.address() as net.AddressInfo).port}/`
  await loadBlocklists()
  if (prevBl === undefined) delete process.env.BROWSER_BLOCKLISTS
  else process.env.BROWSER_BLOCKLISTS = prevBl

  const hOpen = await setupHarness(t, { maxLogBytes: 100 }, { hosts: ['erp.example'], open: true })
  hOpen.site.via!.hosts = ['erp.example', 'other.example']

  const sendHttps = (sPath: string, host: string, reqPath: string) => new Promise<string>((resolve, reject) => {
    const raw = net.connect(sPath)
    raw.once('error', reject)
    raw.write(`CONNECT ${host}:443 HTTP/1.1\r\nhost: ${host}:443\r\n\r\n`)
    raw.once('data', () => {
      const sock = tls.connect({ socket: raw, rejectUnauthorized: false, servername: host })
      sock.once('error', reject)
      const chunks: Buffer[] = []
      sock.on('data', c => chunks.push(c))
      sock.on('end', () => resolve(Buffer.concat(chunks).toString()))
      sock.write(`POST ${reqPath} HTTP/1.1\r\nhost: ${host}\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}`)
    })
  })

  // Write to site.hosts (erp.example) refused 403 audit log full
  const erpFull = await sendHttps(hOpen.sockPath, 'erp.example', '/pay')
  assert.match(erpFull, /^HTTP\/1\.1 403/)
  assert.match(erpFull, /audit log full/)

  // Write to non-site host (other.example) is NOT refused 403 audit log full; it counts as dropped
  const otherFull = await sendHttps(hOpen.sockPath, 'other.example', '/beacon')
  assert.doesNotMatch(otherFull, /^HTTP\/1\.1 403/, 'non-site-host write must not be refused 403 when log is full')
  const openSnap = hOpen.proxy.controller.finalizeAtSeal()
  assert.equal(openSnap.refusedFull, 1)
  assert.ok(openSnap.droppedGets >= 1)

  // GET to t.example still succeeds (200) even when site writes are refused 403
  const getWhenFull = await sendReq('GET', '/still-works')
  assert.equal(getWhenFull.status, 200)

  const snap = proxy.controller.finalizeAtSeal()
  assert.ok(snap.refusedFull >= 1)
  assert.ok(log.some(e => e.rec === '_summary'))
})

test('internalHosts refuses private/internal IPs for all hosts not in internalHosts', async t => {
  const { sendReq } = await setupHarness(t, undefined, {
    hosts: ['10.1.2.3', '192.168.1.5'],
    internalHosts: ['10.1.2.3'],
    via: undefined,
  })
  // 192.168.1.5 is exact-listed in site.hosts, NOT in internalHosts -> refused 403 internal address!
  const blocked = await sendReq('GET', '/', {}, undefined, '192.168.1.5')
  assert.equal(blocked.status, 403)
  assert.match(blocked.body, /internal address/)

  // Empty internalHosts: [] refuses private IP even if exact-listed in site.hosts
  const h2 = await setupHarness(t, undefined, {
    hosts: ['10.1.2.3'],
    internalHosts: [],
    via: undefined,
  })
  const blocked2 = await h2.sendReq('GET', '/', {}, undefined, '10.1.2.3')
  assert.equal(blocked2.status, 403)
  assert.match(blocked2.body, /internal address/)
})

test('exit scrubDeep scrubs vault secrets from URLs, Referers, bodyShape keys, and errors', async t => {
  const vault = new SecretVault()
  vault.addTrustedDrive('TopSecretRef99')
  const { sendReq, log } = await setupHarness(t, { vault })
  await sendReq('POST', '/check/TopSecretRef99?q=TopSecretRef99', {
    referer: 'https://t.example/page/TopSecretRef99',
    'content-type': 'application/json',
  }, JSON.stringify({ TopSecretRef99: 'x', ok: 1 }))
  const json = JSON.stringify(log)
  assert.ok(!json.includes('TopSecretRef99'), 'vault secret never appears anywhere in proxy log')
  assert.ok(json.includes('[REDACTED:vault]'))
})

test('finalizeAtSeal records in-flight POST as dispatch: unknown, preserves bodyShape, and releases ByteBudget to 0', async t => {
  const byteBudget = new ByteBudget()
  const { sockPath, upPort, setHandler, proxy, log } = await setupHarness(t, { byteBudget })
  let reqArrivedResolve!: () => void
  const reqArrived = new Promise<void>(r => { reqArrivedResolve = r })
  setHandler((_req, _res) => { reqArrivedResolve() })

  const req = http.request({
    socketPath: sockPath,
    method: 'POST',
    path: `http://t.example:${upPort}/hang`,
    headers: { host: `t.example:${upPort}`, 'content-type': 'application/json' },
  })
  req.on('error', () => {})
  req.end('{"pending":true,"amount":42}')
  await reqArrived

  assert.ok(byteBudget.getUsedBytes() > 0)
  proxy.controller.finalizeAtSeal()
  assert.equal(byteBudget.getUsedBytes(), 0)

  const entry = log.find((e): e is V2Entry => !e.rec && e.path === '/hang')
  const summary = log.find(e => e.rec === '_summary')
  assert.ok(entry)
  assert.equal(entry.dispatch, 'unknown')
  assert.equal(entry.incomplete, true)
  assert.deepEqual(entry.bodyShape, { pending: 'boolean', amount: 'number' })
  assert.equal(summary?.incompleteAtSeal, 1)
})

test('seal() times out hanging storageState() and pw.close() and resolves promptly with state: null', async () => {
  const dir = fs.mkdtempSync(`${os.tmpdir()}/rf-seal-timeout-`)
  const s = new BrowserSession('seal-to-test', dir, 'test-label', { hosts: [] }, false, { sealTimeoutMs: 50 })
  s.pw = {
    isConnected: () => true,
    contexts: () => [{ storageState: () => new Promise(() => {}) }],
    close: () => new Promise(() => {}),
  } as any

  const t0 = performance.now()
  const snap = await s.seal()
  const elapsed = performance.now() - t0
  assert.equal(snap.sealed, true)
  assert.equal(snap.state, null)
  assert.ok(elapsed < 1000, `seal() should not hang (took ${elapsed.toFixed(0)}ms)`)
})
