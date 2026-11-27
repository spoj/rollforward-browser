import { test } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { once } from 'node:events'
import fs from 'node:fs'
import http from 'node:http'
import net from 'node:net'
import os from 'node:os'
import {
  InFlightBudgetTracker,
  startProxy,
  toLegacyLog,
  type LogRecord,
  type PolicyHookConfig,
  type ProxyV2Options,
  type RequestDescriptor,
  type V2Entry,
} from '../src/proxy.ts'
import { SecretVault } from '../src/redact.ts'

const pem = execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=test', '-keyout', '-', '-out', '-'], { stdio: ['ignore', 'pipe', 'ignore'] }).toString()
const tlsKey = { key: pem.slice(0, pem.indexOf('-----BEGIN CERTIFICATE')), cert: pem.slice(pem.indexOf('-----BEGIN CERTIFICATE')) }

async function setupHarness(t: any, proxyOpts?: ProxyV2Options) {
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

  // Local CONNECT via proxy to route t.example directly to 127.0.0.1:upPort without needing external DNS
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
  const site = {
    hosts: ['t.example'],
    via: { url: `http://127.0.0.1:${viaPort}`, token: 'via-tok', hosts: ['t.example'] },
  }
  const proxy = startProxy(sockPath, site, tlsKey, () => false, log, undefined, undefined, {
    auditV2: { v: 2, projection: 'semantic' },
    siteName: 'erp',
    ...proxyOpts,
  })
  await once(proxy, 'listening')

  t.after(() => {
    proxy.close()
    proxy.closeAllConnections?.()
    viaProxy.close()
    viaProxy.closeAllConnections?.()
    upstream.close()
    upstream.closeAllConnections?.()
    fs.rmSync(dir, { recursive: true, force: true })
  })

  const sendReq = (method: string, path: string, headers: Record<string, string> = {}, body?: Buffer | string) =>
    new Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }>((resolve, reject) => {
      const req = http.request({
        socketPath: sockPath,
        method,
        path: `http://t.example:${upPort}${path}`,
        headers: { host: `t.example:${upPort}`, ...headers },
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
    site,
    log,
    proxy,
    upstreamHits,
    sendReq,
    setHandler: (fn: typeof upstreamHandler) => { upstreamHandler = fn },
  }
}

test('method override escalation only: POST+Override:GET stays write; lowercase/conflict/invalid override and body on safe verb force isWrite', async t => {
  const { sendReq, log } = await setupHarness(t)

  await sendReq('POST', '/a', { 'x-http-method-override': 'GET', 'content-type': 'application/json' }, '{"x":1}')
  await sendReq('GET', '/b', { 'x-http-method-override': 'delete' })
  await sendReq('GET', '/c', { 'x-http-method-override': 'GET, DELETE' })
  await sendReq('GET', '/d', { 'x-http-method-override': 'bad!verb' })
  await sendReq('OPTIONS', '/e', { 'content-type': 'application/json', 'content-length': '7' }, '{"a":1}')

  const entries = log.filter((e): e is V2Entry => typeof (e as any).n === 'number')
  assert.equal(entries.length, 5)
  assert.equal(entries[0].isWrite, true, 'POST + Override: GET stays isWrite')
  assert.equal(entries[0].effectiveMethod, 'POST', 'never downgrades effectiveMethod')
  assert.equal(entries[1].isWrite, true)
  assert.equal(entries[1].effectiveMethod, 'DELETE')
  assert.equal(entries[2].isWrite, true)
  assert.equal(entries[2].hdrConflict, true)
  assert.equal(entries[3].isWrite, true)
  assert.equal(entries[4].isWrite, true, 'OPTIONS with body forces isWrite')
})

test('Expect: 100-continue captures body and strips expect upstream; unsupported Expect returns 417 without reaching upstream', async t => {
  const seenDescs: RequestDescriptor[] = []
  const hook: PolicyHookConfig = {
    mode: 'enforce',
    evaluate: (d, ctx) => {
      seenDescs.push(d)
      return { decisionId: ctx.decisionId, mode: 'enforce', stage: 1, action: 'allow', ruleId: 'ok', policyVersion: '1', ms: 0 }
    },
  }
  const { sendReq, upstreamHits, log } = await setupHarness(t, { policyHook: hook })

  const r1 = await sendReq('POST', '/continue', { expect: '100-continue', 'content-type': 'application/json' }, '{"hello":"world"}')
  assert.equal(r1.status, 200)
  assert.equal(upstreamHits.length, 1)
  assert.equal(upstreamHits[0].headers['expect'], undefined, 'expect header stripped upstream')
  assert.equal(upstreamHits[0].body.toString(), '{"hello":"world"}')
  assert.equal(seenDescs.length, 1)
  assert.equal((seenDescs[0].raw?.parsedBody as any)?.hello, 'world')

  const r2 = await sendReq('POST', '/bad-expect', { expect: '999-unknown' }, 'abc')
  assert.equal(r2.status, 417)
  assert.equal(upstreamHits.length, 1, 'unsupported Expect never reaches upstream')
  assert.ok(log.some((e: any) => e.status === 417 && e.blocked === 'expectation failed'))
})

test('enforce AdmissionHook denies with zero upstream bytes, Connection: close on unread upload, fails closed on throw/timeout, and forwards exact bytes across 64 KiB boundary', async t => {
  let mode: 'allow' | 'deny' | 'throw' | 'timeout' | 'revoke' = 'deny'
  let revokeFn: (() => void) | undefined
  const hook: PolicyHookConfig = {
    mode: 'enforce',
    deadlineMs: 80,
    evaluate: async (_d, ctx) => {
      if (mode === 'throw') throw new Error('boom')
      if (mode === 'timeout') await new Promise(r => setTimeout(r, 250))
      if (mode === 'revoke') {
        revokeFn?.()
        return { decisionId: ctx.decisionId, mode: 'enforce', stage: 1, action: 'allow', ruleId: 'ok', policyVersion: '1', ms: 1 }
      }
      if (mode === 'deny') {
        return { decisionId: ctx.decisionId, mode: 'enforce', stage: 2, action: 'deny', ruleId: 'no-delete', policyVersion: '1', ms: 2 }
      }
      return { decisionId: ctx.decisionId, mode: 'enforce', stage: 1, action: 'allow', ruleId: 'allow-all', policyVersion: '1', ms: 1 }
    },
  }
  const { sendReq, upstreamHits, log, site } = await setupHarness(t, { policyHook: hook })

  // 1. Deny on >64 KiB payload: zero bytes upstream, 403 JSON with ruleId+decisionId only, Connection: close
  const bigBody = crypto.randomBytes(90_000)
  const rDeny = await sendReq('POST', '/big-deny', { 'content-type': 'application/octet-stream' }, bigBody)
  assert.equal(rDeny.status, 403)
  assert.equal(rDeny.headers.connection, 'close')
  const denyJson = JSON.parse(rDeny.body)
  assert.deepEqual(Object.keys(denyJson).sort(), ['decisionId', 'error', 'ruleId'])
  assert.equal(denyJson.ruleId, 'no-delete')
  assert.equal(upstreamHits.length, 0, 'zero bytes reached upstream on deny')

  // 2. Hook throw fails closed
  mode = 'throw'
  const rThrow = await sendReq('POST', '/throw', {}, 'x')
  assert.equal(rThrow.status, 403)
  assert.equal(JSON.parse(rThrow.body).ruleId, 'policy_error')
  assert.equal(upstreamHits.length, 0)

  // 3. Hook timeout fails closed
  mode = 'timeout'
  const rTimeout = await sendReq('POST', '/timeout', {}, 'x')
  assert.equal(rTimeout.status, 403)
  assert.equal(JSON.parse(rTimeout.body).ruleId, 'policy_error')
  assert.equal(upstreamHits.length, 0)

  // 4. Exact 64 KiB boundary & >64 KiB straddling chunks forwarded byte-for-byte unchanged
  mode = 'allow'
  const exact64 = crypto.randomBytes(65_536)
  const r64 = await sendReq('POST', '/exact64', { 'content-type': 'application/octet-stream' }, exact64)
  assert.equal(r64.status, 200)
  assert.equal(upstreamHits.length, 1)
  assert.ok(upstreamHits[0].body.equals(exact64), 'exact 64 KiB body forwarded byte-for-byte unchanged')

  const over100 = crypto.randomBytes(100_000)
  const r100 = await sendReq('POST', '/over100', { 'content-type': 'application/octet-stream' }, over100)
  assert.equal(r100.status, 200)
  assert.equal(upstreamHits.length, 2)
  assert.ok(upstreamHits[1].body.equals(over100), '100 KiB body forwarded byte-for-byte unchanged')

  // 5. PUT /hosts revocation during async hook rechecks check(url)
  mode = 'revoke'
  revokeFn = () => { site.hosts = [] }
  const rRev = await sendReq('POST', '/revoked', {}, 'abc')
  assert.equal(rRev.status, 403)
  assert.equal(upstreamHits.length, 2, 'revoked host blocked before upstream dispatch')
  assert.ok(log.some((e: any) => e.blocked === 'host not on the list'))
})

test('forwardUpgrade invokes enforce AdmissionHook and blocks denied upgrades before upstream', async t => {
  let allow = false
  const hook: PolicyHookConfig = {
    mode: 'enforce',
    evaluate: (_d, ctx) => ({ decisionId: ctx.decisionId, mode: 'enforce', stage: 1, action: allow ? 'allow' : 'deny', ruleId: 'ws-rule', policyVersion: '1', ms: 0 }),
  }
  const { sockPath, upPort, upstreamHits, log } = await setupHarness(t, { policyHook: hook })

  const tryUpgrade = () => new Promise<string>(resolve => {
    const s = net.connect(sockPath)
    s.write(`GET http://t.example:${upPort}/ws HTTP/1.1\r\nhost: t.example:${upPort}\r\nupgrade: websocket\r\nconnection: upgrade\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n\r\n`)
    const chunks: Buffer[] = []
    s.on('data', c => chunks.push(c))
    s.on('end', () => resolve(Buffer.concat(chunks).toString()))
  })

  const r1 = await tryUpgrade()
  assert.match(r1, /^HTTP\/1\.1 403/)
  assert.match(r1, /"ruleId":"ws-rule"/, 'upgrade policy denial includes structured JSON ruleId & decisionId')
  assert.equal(upstreamHits.length, 0)
  allow = true
  assert.match(await tryUpgrade(), /^HTTP\/1\.1 101/)
  assert.equal(upstreamHits.length, 1)
  assert.ok(log.some((e: any) => e.kind === 'upgrade' && e.status === 403))
  assert.ok(log.some((e: any) => e.kind === 'upgrade' && e.status === 101))
})

test('shadow mode adds zero latency and emits policy via http_end when hook settles after response', async t => {
  const hook: PolicyHookConfig = {
    mode: 'shadow',
    evaluate: async (_d, ctx) => {
      await new Promise(r => setTimeout(r, 120))
      return { decisionId: ctx.decisionId, mode: 'shadow', stage: 2, action: 'escalate', ruleId: 'shadow-rule', policyVersion: '1', ms: 120 }
    },
  }
  const { sendReq, log } = await setupHarness(t, { policyHook: hook })
  const t0 = performance.now()
  const r = await sendReq('POST', '/fast', { 'content-type': 'application/json' }, '{"k":1}')
  const elapsed = performance.now() - t0
  assert.equal(r.status, 200)
  assert.ok(elapsed < 100, `shadow mode must not delay response (took ${elapsed}ms)`)
  await new Promise(r => setTimeout(r, 200))
  const late = log.find((e: any) => e.rec === 'http_end') as any
  assert.ok(late, 'emitted late http_end with shadow policy decision')
  assert.equal(late.policy.ruleId, 'shadow-rule')
  // Legacy allowlist strips http_end and v2 fields
  const legacy = toLegacyLog(log)
  assert.equal(legacy.length, 1)
  assert.deepEqual(Object.keys(legacy[0]).sort(), ['method', 'status', 't', 'url'])
})

test('long-lived stream emits immutable incomplete Entry at streamTimeoutMs and separate LateOutcomeEntry on completion', async t => {
  const { sendReq, setHandler, log } = await setupHarness(t, { streamTimeoutMs: 60 })
  setHandler((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' })
    res.write('data: hello\n\n')
    setTimeout(() => res.end('data: bye\n\n'), 160)
  })
  const r = await sendReq('GET', '/events')
  assert.equal(r.status, 200)
  const first = log.find((e: any) => e.incomplete === true) as V2Entry
  const late = log.find((e: any) => e.rec === 'http_end') as any
  assert.ok(first, 'emitted incomplete Entry at streamTimeoutMs')
  assert.ok(late, 'emitted separate LateOutcomeEntry on stream end')
  assert.equal(late.ref, first.n)
  assert.ok(late.resBytes > 0)
})

test('byte budgets collapse static GETs, preserve origin+pathname in logCapped mode, and fail closed with 403 audit log full', async t => {
  const { sendReq, log, proxy } = await setupHarness(t, {
    collapseGetsAfterBytes: 100,
    collapseGetsAfterEntries: 2,
    maxLogSoftBytes: 1500,
    maxLogHardBytes: 64 * 1024 + 3600, // 3600 B above 64 KiB tail reserve
  })
  // Emit a few static GETs -> should collapse into collapsedGets
  for (let i = 0; i < 6; i++) {
    await sendReq('GET', `/img/${i}.png`, { 'sec-fetch-dest': 'image' })
  }
  // Flood writes until hard log ceiling is reached
  let got403Full = false
  for (let i = 0; i < 20; i++) {
    const r = await sendReq('POST', `/write/${i}`, { 'content-type': 'application/json' }, JSON.stringify({ n: i }))
    if (r.status === 403 && r.body.includes('audit log full')) {
      got403Full = true
      break
    }
  }
  assert.equal(got403Full, true, 'fails closed with 403 audit log full at hard cap')
  const capped = log.filter((e: any) => e.logCapped === true) as V2Entry[]
  assert.ok(capped.length > 0, 'emitted logCapped minimal entries above soft cap')
  for (const e of capped) {
    assert.equal(new URL(e.url).hostname, 't.example', 'logCapped preserves origin+pathname for checkRefused')
  }
  const snap = proxy.controller.finalizeAtSeal()
  assert.ok(snap.refusedFull >= 1)
  const summary = log.find((e: any) => e.rec === '_summary') as any
  assert.ok(summary, 'appended _summary inside reserved tail budget')
  assert.ok(Object.keys(summary.collapsedGets).length > 0, 'collapsed static GETs recorded in _summary')
})

test('in-flight budget exhaustion in enforce mode fails closed with 503', async t => {
  const tracker = new InFlightBudgetTracker(32, 32, 32)
  const hook: PolicyHookConfig = {
    mode: 'enforce',
    evaluate: (_d, ctx) => ({ decisionId: ctx.decisionId, mode: 'enforce', stage: 1, action: 'allow', ruleId: 'ok', policyVersion: '1', ms: 0 }),
  }
  const { sendReq, upstreamHits } = await setupHarness(t, { policyHook: hook, inFlightTracker: tracker })
  const r = await sendReq('POST', '/too-big-for-budget', {}, 'x'.repeat(256))
  assert.equal(r.status, 503)
  assert.equal(upstreamHits.length, 0)
  assert.equal(tracker.getProcessBytes(), 0, 'budget released cleanly')
})

test('vault scrubs errors and Referer headers without crashing', async t => {
  const vault = new SecretVault()
  vault.addTrustedDrive('TopSecretRef99')
  const { sendReq, log } = await setupHarness(t, { vault })
  await sendReq('GET', '/check', { referer: 'https://t.example/page/TopSecretRef99' })
  const entry = log[0] as V2Entry
  assert.ok(!entry.from!.includes('TopSecretRef99'))
  assert.ok(entry.from!.includes('[REDACTED:vault]'))
})

test('P2-5 finalizeAtSeal records in-flight POST as dispatch: unknown, preserves bodyShape, and releases observe-mode budget to 0', async t => {
  const tracker = new InFlightBudgetTracker()
  const { sockPath, upPort, setHandler, proxy, log } = await setupHarness(t, { inFlightTracker: tracker })
  let reqArrivedResolve!: () => void
  const reqArrived = new Promise<void>(r => { reqArrivedResolve = r })
  setHandler((_req, _res) => {
    // Request body has already finished arriving at upstream; hold response open so POST is in-flight at seal!
    reqArrivedResolve()
  })

  const req = http.request({
    socketPath: sockPath,
    method: 'POST',
    path: `http://t.example:${upPort}/hang`,
    headers: { host: `t.example:${upPort}`, 'content-type': 'application/json' },
  })
  req.on('error', () => {})
  req.end('{"pending":true,"amount":42}')
  await reqArrived
  // Allow microtask eager projection build on prefixFrozenPromise to complete
  await new Promise(r => setTimeout(r, 15))

  assert.ok(tracker.getProcessBytes() > 0, 'in-flight observe request holds tee budget before seal')
  proxy.controller.finalizeAtSeal()
  assert.equal(tracker.getProcessBytes(), 0, 'finalizeAtSeal releases all observe-mode tee & decoded budget')

  const entry = log.find((e: any) => e.path === '/hang') as V2Entry
  const summary = log.find((e: any) => e.rec === '_summary') as any
  assert.ok(entry, 'in-flight POST recorded at seal')
  assert.equal(entry.dispatch, 'unknown')
  assert.equal(entry.incomplete, true)
  assert.deepEqual(entry.bodyShape, { pending: 'boolean', amount: 'number' }, 'bodyShape preserved on sealed in-flight POST')
  assert.equal(summary.incompleteAtSeal, 1)
})

test('P2-6 explicit checkSync Stage-1 GET bypasses async cap while non-async function returning Promise is capped before invocation', async t => {
  const releases: Array<() => void> = []
  let getEvaluateInvoked = 0
  const hook: PolicyHookConfig = {
    mode: 'enforce',
    checkSync: (d, ctx) => {
      if (!d.safe.isWrite && d.safe.path === '/sync-read') {
        return { decisionId: ctx.decisionId, mode: 'enforce', stage: 1, action: 'allow', ruleId: 'sync-get', policyVersion: '1', ms: 0 }
      }
      return undefined
    },
    // Non-async function returning a Promise (NOT an AsyncFunction!)
    evaluate: (d, ctx) => {
      if (!d.safe.isWrite) getEvaluateInvoked++
      return new Promise(resolve => {
        releases.push(() => resolve({ decisionId: ctx.decisionId, mode: 'enforce', stage: 2, action: 'allow', ruleId: 'async-hook', policyVersion: '1', ms: 1 }))
      })
    },
  }
  const { sendReq } = await setupHarness(t, { policyHook: hook, maxConcurrentAsyncHooks: 2 })
  const w1 = sendReq('POST', '/w1', {}, 'a')
  const w2 = sendReq('POST', '/w2', {}, 'b')
  while (releases.length < 2) await new Promise(r => setTimeout(r, 5))

  // 3rd write fails closed with 503 while 2 async hooks are saturated
  const w3 = await sendReq('POST', '/w3', {}, 'c')
  assert.equal(w3.status, 503)

  // Non-async Promise-returning evaluate() on GET MUST fail closed BEFORE invoking evaluate()!
  const asyncGet = await sendReq('GET', '/async-read')
  assert.equal(asyncGet.status, 503)
  assert.equal(getEvaluateInvoked, 0, 'non-async Promise-returning GET hook must NOT be invoked when cap is full')

  // Explicit checkSync Stage-1 GET still passes with 200!
  const syncGet = await sendReq('GET', '/sync-read')
  assert.equal(syncGet.status, 200)

  for (const r of releases) r()
  assert.equal((await w1).status, 200)
  assert.equal((await w2).status, 200)
})
