import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { spawn, execFileSync, type ChildProcess } from 'node:child_process'
import { once } from 'node:events'
import fs from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import { chromium } from 'playwright-core'
import { startPortal } from './portal.ts'

const port = 8801
const key1 = 'v3-client-1'
const key2 = 'v3-client-2'
const auth = (k = key1) => ({ authorization: `Bearer ${k}` })

const api = async (method: string, path: string, body?: unknown, key = key1) => {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: auth(key),
    body: typeof body === 'string' || body === undefined ? body : JSON.stringify(body),
  })
  const ct = res.headers.get('content-type') ?? ''
  return {
    status: res.status,
    headers: res.headers,
    body: ct.includes('application/json') ? await res.json() : Buffer.from(await res.arrayBuffer()),
  }
}

const tmp = fs.mkdtempSync(`${os.tmpdir()}/rf-v3-integ-`)
const openssl = (...args: string[]) => execFileSync('openssl', args, { cwd: tmp, stdio: 'ignore' })
let portal: ReturnType<typeof startPortal>
let service: ChildProcess
let site: { hosts: string[]; start_url: string }

before(async () => {
  openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=test-ca', '-days', '1', '-keyout', 'ca.key', '-out', 'ca.pem')
  openssl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=portal.localhost', '-keyout', 'portal.key', '-out', 'portal.csr')
  fs.writeFileSync(`${tmp}/san`, 'subjectAltName=DNS:portal.localhost,DNS:other.localhost\n')
  openssl('x509', '-req', '-in', 'portal.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '1', '-extfile', 'san', '-out', 'portal.pem')
  portal = startPortal({ key: fs.readFileSync(`${tmp}/portal.key`, 'utf8'), cert: fs.readFileSync(`${tmp}/portal.pem`, 'utf8') })
  await once(portal.server, 'listening')
  site = { hosts: ['portal.localhost'], start_url: `https://portal.localhost:${portal.port()}/` }
  service = spawn('node', ['--import', './test/resolve.ts', 'src/server.ts'], {
    env: {
      ...process.env,
      BROWSER_PORT: String(port),
      BROWSER_KEYS: `c1:${key1} c2:${key2}`,
      BROWSER_BLOCKLISTS: '',
      NODE_EXTRA_CA_CERTS: `${tmp}/ca.pem`,
    },
    stdio: ['ignore', 'pipe', 'inherit'],
  })
  await Promise.race([once(service.stdout!, 'data'), once(service, 'exit').then(() => { throw new Error('service exited') })])
})

after(() => {
  service.kill()
  portal.server.close()
  fs.rmSync(tmp, { recursive: true, force: true })
})

const leftovers = () =>
  execFileSync('podman', ['ps', '-a', '-q', '--filter', `label=rollforward-browser=${port}`]).toString().trim() +
  fs.readdirSync(`${os.tmpdir()}/rollforward-browser-${port}`).join(' ')

test('GET /capabilities advertises v0.3.1, POST /sessions validates auditV2, and rejects dropped semantic+samples projection', async () => {
  const cap = await api('GET', '/capabilities')
  assert.deepEqual(cap.body, { version: '0.3.1', auditV2: 2, seal: true, activity: true })
  assert.equal(cap.status, 200)

  assert.equal((await api('POST', '/sessions', { site, auditV2: { v: 99 } })).status, 400)
  assert.equal((await api('POST', '/sessions', { site, auditV2: { v: 2, projection: 'semantic+samples' } })).status, 400)
})

test('audit: true without auditV2 opens a v2 session with shots enabled (RF v0.11.0 compat bridge)', async () => {
  const opened = await api('POST', '/sessions', { site, audit: true })
  assert.equal(opened.status, 201)
  const { id, seal, shots, cdpLog, activity } = opened.body
  assert.equal(seal, `/sessions/${id}/seal`)
  assert.equal(shots, `/sessions/${id}/shots`)
  assert.equal(cdpLog, `/sessions/${id}/cdp-log`)
  assert.equal(activity, `/sessions/${id}/view/activity`)

  const shotsEnv = await api('GET', `${shots}?after=0`)
  assert.equal(shotsEnv.status, 200)
  assert.equal(typeof shotsEnv.body.hasMore, 'boolean')
  assert.equal(Array.isArray(shotsEnv.body.items), true)

  await api('DELETE', `/sessions/${id}`)
  assert.equal(leftovers(), '')
})

test('end-to-end: /view/drive tapped into CDP log with live:true + OTP vault scrub, /cdp uniform callFunctionOn, log-derived HUD, seal -> drain -> DELETE?sealed=1, and cross-client isolation', async () => {
  const opened = await api('POST', '/sessions', {
    site,
    audit: true,
    auditV2: { v: 2, cdp: true, hud: true },
  })
  assert.equal(opened.status, 201)
  const { id, cdp, view, seal, logV2, cdpLog, shots, activity } = opened.body

  for (const [m, p] of [['POST', seal], ['GET', `${logV2}?after=0`], ['GET', `${cdpLog}?after=0`], ['GET', `${shots}?after=0`], ['GET', `${activity}?after=0`]] as const) {
    assert.equal((await api(m, p, undefined, key2)).status, 404, `other client blocked from ${p}`)
  }

  // Human drives /view/drive to sign in and types a 6-digit OTP with Backspace edit ("739104" typed as 739109 + Backspace + 4)
  const driver = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${view}/drive`, { headers: auth() })
  const dPage = driver.contexts()[0].pages()[0]
  await dPage.waitForURL(/\/login$/)
  await dPage.fill('#user', 'ann')
  await dPage.fill('#password', 'secret')
  await dPage.click('#user')
  await dPage.keyboard.type('739109')
  await dPage.keyboard.press('Backspace')
  await dPage.keyboard.type('4')
  await dPage.keyboard.press('Enter')
  await dPage.waitForSelector('text=Welcome ann')
  await driver.close()

  // External Playwright agent over /cdp triggers write carrying the human-typed OTP + evaluate + setFileInputFiles
  const agent = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${cdp}`, { headers: auth() })
  const page = agent.contexts()[0].pages()[0]
  await page.evaluate(() => fetch('/update?note=739104', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ otpEcho: '739104', amount: 42.50 }) }).then(r => r.status))
  await page.setContent('<input id="f" type="file"><p>Ready</p>')
  await api('PUT', `/sessions/${id}/files/tmp/doc.txt`, 'hello')
  const cdpSession = await agent.contexts()[0].newCDPSession(page)
  const doc = await cdpSession.send('DOM.getDocument')
  const node = await cdpSession.send('DOM.querySelector', { nodeId: doc.root.nodeId, selector: '#f' })
  await cdpSession.send('DOM.setFileInputFiles', { nodeId: node.nodeId, files: ['/tmp/doc.txt'] })
  await agent.close()

  // Log-derived /view/activity HUD returns no-store and hides live-period events
  const hud = await api('GET', `${activity}?after=0`)
  assert.equal(hud.status, 200)
  assert.equal(hud.headers.get('cache-control'), 'no-store')
  assert.equal(hud.body.live, false)
  assert.ok(!JSON.stringify(hud.body).includes('739104'))

  // Idempotent POST /seal
  const snap1 = await api('POST', seal)
  assert.equal(snap1.status, 200)
  assert.equal(snap1.body.sealed, true)
  assert.ok(snap1.body.state?.cookies?.some((c: any) => c.name === 'sid'))
  assert.ok(snap1.body.logCursor > 0)
  assert.ok(snap1.body.cdpCursor > 0)
  assert.deepEqual((await api('POST', seal)).body, snap1.body)

  // Active-only routes return 410 after seal
  assert.equal((await api('GET', `/sessions/${id}/page`)).status, 410)
  assert.equal((await api('GET', activity)).status, 410)

  // Drain /log?after=0
  const logPage = await api('GET', `${logV2}?after=0&limit=500`)
  assert.equal(logPage.status, 200)
  assert.equal(logPage.body.nextCursor, snap1.body.logCursor)
  assert.equal(logPage.body.hasMore, false)
  const entries = logPage.body.entries as any[]
  assert.ok(entries.some(e => e.rec === '_summary'))
  assert.ok(entries.some(e => e.path === '/update' && e.isWrite === true))
  assert.ok(!JSON.stringify(entries).includes('739104'), 'OTP scrubbed from HTTP log')

  // Drain /cdp-log?after=0: includes /view/drive commands with live: true AND agent commands without wrapper fingerprinting
  const cdpPage = await api('GET', `${cdpLog}?after=0&limit=500`)
  assert.equal(cdpPage.status, 200)
  assert.equal(cdpPage.body.nextCursor, snap1.body.cdpCursor)
  assert.equal(cdpPage.body.hasMore, false)
  const cdpEntries = cdpPage.body.entries as any[]
  assert.ok(cdpEntries.some(e => e.rec === '_tap.summary'))
  assert.ok(cdpEntries.some(e => e.live === true), '/view/drive commands tapped into CDP log with live: true')
  assert.ok(cdpEntries.some(e => e.method === 'Runtime.callFunctionOn' && typeof e.summary?.fnLen === 'number' && typeof e.summary?.fnHash64 === 'string' && typeof e.summary?.argCount === 'number' && !('wrapper' in e.summary)))
  assert.ok(cdpEntries.some(e => e.method === 'DOM.setFileInputFiles'))
  assert.ok(!JSON.stringify(cdpEntries).includes('739104'), 'OTP scrubbed from CDP log')

  // DELETE ?sealed=1 reclaims
  assert.deepEqual((await api('DELETE', `/sessions/${id}?sealed=1`)).body, { deleted: true })
  assert.equal((await api('DELETE', `/sessions/${id}?sealed=1`)).status, 404)
  assert.equal(leftovers(), '')
})

test('CDP tap fails closed by closing socket on malformed WebSocket frame', async () => {
  const opened = await api('POST', '/sessions', { site })
  assert.equal(opened.status, 201)
  const { id, cdp } = opened.body

  const sock = net.connect(port, '127.0.0.1')
  await once(sock, 'connect')
  const key = crypto.randomBytes(16).toString('base64')
  sock.write(
    `GET ${cdp} HTTP/1.1\r\n` +
    `Host: 127.0.0.1:${port}\r\n` +
    `Upgrade: websocket\r\n` +
    `Connection: Upgrade\r\n` +
    `Authorization: Bearer ${key1}\r\n` +
    `Sec-WebSocket-Key: ${key}\r\n` +
    `Sec-WebSocket-Version: 13\r\n\r\n`,
  )
  // Wait for 101 handshake
  const firstChunk = (await once(sock, 'data'))[0] as Buffer
  assert.match(firstChunk.toString(), /^HTTP\/1\.1 101/)

  // Send an unmasked client->server frame (protocol violation) -> server MUST close the socket immediately
  const closed = once(sock, 'close')
  sock.write(Buffer.from([0x81, 0x02, 0x7b, 0x7d]))
  await Promise.race([
    closed,
    new Promise((_, rej) => setTimeout(() => rej(new Error('CDP socket stayed open after protocol violation')), 1500)),
  ])

  await api('DELETE', `/sessions/${id}?sealed=1`)
  assert.equal(leftovers(), '')
})

test('internalHosts allows listed internal host and refuses private IP for unlisted host at connect time', async () => {
  const opened = await api('POST', '/sessions', {
    site: { hosts: ['portal.localhost', 'other.localhost'], start_url: site.start_url },
    internalHosts: ['portal.localhost'],
  })
  assert.equal(opened.status, 201)
  const { id, cdp } = opened.body
  const agent = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${cdp}`, { headers: auth() })
  const page = agent.contexts()[0].pages()[0]
  assert.equal((await page.goto(`${site.start_url}login`))!.status(), 200, 'host in internalHosts reaches private IP')
  const blocked = await page.goto(`https://other.localhost:${portal.port()}/`)
  assert.equal(blocked!.status(), 502, 'host not in internalHosts refused private IP at connect time')
  assert.match(await page.textContent('body') ?? '', /resolves only to internal addresses/)
  await agent.close()
  await api('DELETE', `/sessions/${id}?sealed=1`)
  assert.equal(leftovers(), '')
})

test('per-client sealed cap (503) isolates clients without cross-tenant eviction, and post-TTL GC reclaims all expired sessions', async t => {
  const capPort = 8802
  const capSvc = spawn('node', ['--import', './test/resolve.ts', 'src/server.ts'], {
    env: {
      ...process.env,
      BROWSER_PORT: String(capPort),
      BROWSER_KEYS: `c1:${key1} c2:${key2}`,
      BROWSER_BLOCKLISTS: '',
      BROWSER_MAX_SEALED_PER_CLIENT: '2',
      BROWSER_POST_TTL_GC_MS: '600',
      NODE_EXTRA_CA_CERTS: `${tmp}/ca.pem`,
    },
    stdio: ['ignore', 'pipe', 'inherit'],
  })
  t.after(() => capSvc.kill())
  await Promise.race([once(capSvc.stdout!, 'data'), once(capSvc, 'exit').then(() => { throw new Error('cap service exited') })])

  const capApi = async (method: string, path: string, body?: unknown, key = key1) => {
    const res = await fetch(`http://127.0.0.1:${capPort}${path}`, {
      method,
      headers: auth(key),
      body: body === undefined ? undefined : JSON.stringify(body),
    })
    return { status: res.status, body: await res.json() }
  }

  // Client 1 opens and seals 2 sessions (hitting per-client sealed cap = 2)
  const s1 = await capApi('POST', '/sessions', { site: { hosts: [] } }, key1)
  const s2 = await capApi('POST', '/sessions', { site: { hosts: [] } }, key1)
  assert.equal(s1.status, 201)
  assert.equal(s2.status, 201)
  await capApi('POST', `/sessions/${s1.body.id}/seal`, {}, key1)
  await capApi('POST', `/sessions/${s2.body.id}/seal`, {}, key1)

  // Client 1's 3rd open gets 503 AND does NOT evict s1 or s2
  const s3 = await capApi('POST', '/sessions', { site: { hosts: [] } }, key1)
  assert.equal(s3.status, 503)
  assert.equal((await capApi('GET', `/sessions/${s1.body.id}/log?after=0`, undefined, key1)).status, 200)

  // Client 2 is completely unaffected and can open & TTL-expire its session
  const c2s = await capApi('POST', '/sessions', { site: { hosts: [] }, ttl_s: 0.3 }, key2)
  assert.equal(c2s.status, 201)

  // Wait for post-TTL GC (0.3s TTL + seal + 0.6s GC) -> ALL expired/sealed sessions are GC'd
  await new Promise(r => setTimeout(r, 2500))
  assert.equal((await capApi('GET', `/sessions/${c2s.body.id}/log?after=0`, undefined, key2)).status, 404, 'post-TTL GC reclaims all sessions')
  assert.equal((await capApi('GET', `/sessions/${s1.body.id}/log?after=0`, undefined, key1)).status, 404, 'post-seal GC reclaims sealed sessions')
})
