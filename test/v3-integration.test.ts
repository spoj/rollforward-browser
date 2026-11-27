import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, execFileSync, type ChildProcess } from 'node:child_process'
import { once } from 'node:events'
import fs from 'node:fs'
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

test('GET /capabilities advertises v0.3.0 and POST /sessions validates auditV2.v', async () => {
  const cap = await api('GET', '/capabilities')
  assert.deepEqual(cap.body, { version: '0.3.0', auditV2: 2, seal: true, activity: true })
  assert.equal(cap.status, 200)

  const bad = await api('POST', '/sessions', { site, auditV2: { v: 99 } })
  assert.equal(bad.status, 400)
})

test('legacy audit: true session returns plain JSON array on /shots and 404 on /view/activity and /cdp-log', async () => {
  const opened = await api('POST', '/sessions', { site, audit: true })
  assert.equal(opened.status, 201)
  assert.equal(opened.body.seal, undefined, 'no v2 links on legacy session')
  const { id } = opened.body

  const shots = await api('GET', `/sessions/${id}/shots?after=0`)
  assert.equal(shots.status, 200)
  assert.equal(Array.isArray(shots.body), true, 'legacy /shots returns plain array')

  const shotsV2 = await api('GET', `/sessions/${id}/shots?after=0&v=2`)
  assert.equal(shotsV2.status, 200)
  assert.equal(typeof shotsV2.body.hasMore, 'boolean', '?v=2 returns v2 envelope')

  assert.equal((await api('GET', `/sessions/${id}/view/activity`)).status, 404)
  assert.equal((await api('GET', `/sessions/${id}/cdp-log`)).status, 404)

  await api('DELETE', `/sessions/${id}`)
  assert.equal(leftovers(), '')
})

test('auditV2 end-to-end: Playwright 1.64 CDP tap, human /view/drive OTP vault scrub, /view/activity HUD, idempotent seal -> drain -> DELETE?sealed=1, and cross-client isolation', async () => {
  const opened = await api('POST', '/sessions', {
    site,
    audit: true,
    auditV2: { v: 2, projection: 'semantic+samples', cdp: true, hud: true },
  })
  assert.equal(opened.status, 201)
  const { id, cdp, view, seal, logV2, cdpLog, shots, activity } = opened.body
  assert.equal(seal, `/sessions/${id}/seal`)
  assert.equal(logV2, `/sessions/${id}/log`)
  assert.equal(cdpLog, `/sessions/${id}/cdp-log`)
  assert.equal(activity, `/sessions/${id}/view/activity`)

  // Cross-client isolation on all new routes
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

  // Wait out live cooldown? No — test right after driving & also wait briefly so subsequent agent call isn't marked live,
  // OR check activity HUD has live_start & live_end markers and zero live-period details!
  const hudDuring = await api('GET', `${activity}?after=0`)
  assert.equal(hudDuring.status, 200)
  assert.equal(hudDuring.headers.get('cache-control'), 'no-store')
  assert.ok(hudDuring.body.events.some((e: any) => e.kind === 'live_start'))
  assert.ok(hudDuring.body.events.some((e: any) => e.kind === 'live_end'))

  // Connect external Playwright 1.64 agent over /cdp (MUST be tapped while internal BrowserSession.pw is NOT tapped!)
  const agent = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${cdp}`, { headers: auth() })
  const page = agent.contexts()[0].pages()[0]
  // Trigger a write carrying the human-typed OTP in body + query, plus real Playwright evaluate & setInputFiles
  await page.evaluate(() => fetch('/update?note=739104', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ otpEcho: '739104', amount: 42.50 }) }).then(r => r.status))
  await page.setContent('<input id="f" type="file"><p>Ready</p>')
  await api('PUT', `/sessions/${id}/files/tmp/doc.txt`, 'hello')
  const cdpSession = await agent.contexts()[0].newCDPSession(page)
  const doc = await cdpSession.send('DOM.getDocument')
  const node = await cdpSession.send('DOM.querySelector', { nodeId: doc.root.nodeId, selector: '#f' })
  await cdpSession.send('DOM.setFileInputFiles', { nodeId: node.nodeId, files: ['/tmp/doc.txt'] })
  await agent.close()

  // Idempotent POST /seal freezes session and flushes CDP coalescing + _summary + _tap.summary
  const snap1 = await api('POST', seal)
  assert.equal(snap1.status, 200)
  assert.equal(snap1.body.sealed, true)
  assert.ok(snap1.body.state?.cookies?.some((c: any) => c.name === 'sid'))
  assert.ok(snap1.body.logCursor > 0)
  assert.ok(snap1.body.cdpCursor > 0)

  const snap2 = await api('POST', seal)
  assert.deepEqual(snap2.body, snap1.body, 'POST /seal is strictly idempotent')

  // Active-only routes return 410 after seal, while drain routes remain 200!
  assert.equal((await api('GET', `/sessions/${id}/page`)).status, 410)
  assert.equal((await api('GET', activity)).status, 410)

  // Drain /log?after=0 in pages after seal
  const logPage = await api('GET', `${logV2}?after=0&limit=500`)
  assert.equal(logPage.status, 200)
  assert.equal(logPage.body.nextCursor, snap1.body.logCursor)
  assert.equal(logPage.body.hasMore, false)
  const entries = logPage.body.entries as any[]
  assert.ok(entries.some(e => e.rec === '_summary'), 'log ends with _summary')
  const updateEntry = entries.find(e => e.path === '/update')
  assert.ok(updateEntry, 'captured /update write')
  assert.equal(updateEntry.isWrite, true)
  assert.ok(!JSON.stringify(entries).includes('739104'), 'OTP typed via /view/drive with Backspace scrubbed from entire HTTP log')

  // Unparameterized GET /log returns legacy v0.2.2 allowlist without _summary or v2 fields
  const legacyLog = await api('GET', logV2)
  assert.equal(legacyLog.status, 200)
  assert.equal(Array.isArray(legacyLog.body), true)
  assert.ok(legacyLog.body.every((e: any) => !('rec' in e) && !('actions' in e) && !('descV' in e)))

  // Drain /cdp-log?after=0 after seal
  const cdpPage = await api('GET', `${cdpLog}?after=0&limit=500`)
  assert.equal(cdpPage.status, 200)
  assert.equal(cdpPage.body.nextCursor, snap1.body.cdpCursor)
  assert.equal(cdpPage.body.hasMore, false)
  const cdpEntries = cdpPage.body.entries as any[]
  assert.ok(cdpEntries.some(e => e.rec === '_tap.summary'), 'cdp-log ends with _tap.summary')
  assert.ok(cdpEntries.some(e => e.method === 'Runtime.callFunctionOn' && e.summary?.wrapper === 'playwright-utility'), 'real Playwright 1.64 evaluate captured as playwright-utility')
  assert.ok(cdpEntries.some(e => e.method === 'DOM.setFileInputFiles'), 'real Playwright 1.64 setInputFiles captured')
  assert.ok(!JSON.stringify(cdpEntries).includes('739104'), 'OTP scrubbed from CDP log too')

  // Drain /shots?after=0 returns v2 envelope on auditV2 session
  const shotsPage = await api('GET', `${shots}?after=0`)
  assert.equal(shotsPage.status, 200)
  assert.equal(typeof shotsPage.body.oldestSeq, 'number')
  assert.equal(typeof shotsPage.body.nextSeq, 'number')
  assert.equal(typeof shotsPage.body.hasMore, 'boolean')
  assert.equal(Array.isArray(shotsPage.body.items), true)

  // Acknowledge reclamation via DELETE ?sealed=1
  const del = await api('DELETE', `/sessions/${id}?sealed=1`)
  assert.deepEqual(del.body, { deleted: true })
  assert.equal(del.status, 200)
  assert.equal((await api('DELETE', `/sessions/${id}?sealed=1`)).status, 404)
  assert.equal(leftovers(), '')
})

test('TTL expiry runs seal so v2 logs/cdp-log/shots remain drainable until DELETE?sealed=1', async () => {
  const opened = await api('POST', '/sessions', { site, audit: true, auditV2: { v: 2 }, ttl_s: 0.5 })
  assert.equal(opened.status, 201)
  const { id } = opened.body
  await new Promise(r => setTimeout(r, 1800))

  assert.equal((await api('GET', `/sessions/${id}/page`)).status, 410)
  const logPage = await api('GET', `/sessions/${id}/log?after=0`)
  assert.equal(logPage.status, 200)
  assert.ok(logPage.body.entries.some((e: any) => e.rec === '_summary'))
  const cdpPage = await api('GET', `/sessions/${id}/cdp-log?after=0`)
  assert.equal(cdpPage.status, 200)
  assert.ok(cdpPage.body.entries.some((e: any) => e.rec === '_tap.summary'))
  const shotsPage = await api('GET', `/sessions/${id}/shots?after=0`)
  assert.equal(shotsPage.status, 200)

  assert.equal((await api('DELETE', `/sessions/${id}?sealed=1`)).status, 200)
  assert.equal(leftovers(), '')
})
