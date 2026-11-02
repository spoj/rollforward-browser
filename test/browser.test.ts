import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, execFileSync, type ChildProcess } from 'node:child_process'
import { once } from 'node:events'
import fs from 'node:fs'
import os from 'node:os'
import { chromium } from 'playwright-core'
import { startPortal } from './portal.ts'

const port = 8798
const key = 'test-key'
const headers = { authorization: `Bearer ${key}` }
const api = async (method: string, path: string, body?: unknown) => {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers, body: typeof body === 'string' || body === undefined ? body : JSON.stringify(body) })
  return { status: res.status, body: res.headers.get('content-type') === 'application/json' ? await res.json() : Buffer.from(await res.arrayBuffer()) }
}
const tmp = fs.mkdtempSync(`${os.tmpdir()}/machines-test-`)
const openssl = (...args: string[]) => execFileSync('openssl', args, { cwd: tmp, stdio: 'ignore' })
let portal: ReturnType<typeof startPortal>
let service: ChildProcess
let site: { hosts: string[], start_url: string, reads_that_post: string[] }

before(async () => {
  openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=test-ca', '-days', '1', '-keyout', 'ca.key', '-out', 'ca.pem')
  openssl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=portal.localhost', '-keyout', 'portal.key', '-out', 'portal.csr')
  fs.writeFileSync(`${tmp}/san`, 'subjectAltName=DNS:portal.localhost,DNS:other.localhost,DNS:sub.portal.localhost\n')
  openssl('x509', '-req', '-in', 'portal.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '1', '-extfile', 'san', '-out', 'portal.pem')
  portal = startPortal({ key: fs.readFileSync(`${tmp}/portal.key`, 'utf8'), cert: fs.readFileSync(`${tmp}/portal.pem`, 'utf8') })
  await once(portal.server, 'listening')
  const origin = `https://portal.localhost:${portal.port()}`
  site = { hosts: ['portal.localhost'], start_url: `${origin}/`, reads_that_post: [`${origin}/report*`] }
  service = spawn('node', ['src/server.ts'], { env: { ...process.env, MACHINES_PORT: String(port), MACHINES_KEY: key, NODE_EXTRA_CA_CERTS: `${tmp}/ca.pem` }, stdio: ['ignore', 'pipe', 'inherit'] })
  await Promise.race([once(service.stdout!, 'data'), once(service, 'exit').then(() => { throw new Error('service exited') })])
})

after(() => {
  service.kill()
  portal.server.close()
  fs.rmSync(tmp, { recursive: true })
})

const leftovers = () => execFileSync('podman', ['ps', '-a', '-q', '--filter', `label=machines=${port}`]).toString().trim() + fs.readdirSync(`${os.tmpdir()}/machines-${port}`).join(' ')

let signedIn: any

test('a person signs in through the live view; closing returns the login', async () => {
  const opened = await api('POST', '/sessions', { kind: 'browser', site })
  assert.equal(opened.status, 201)
  const { id, view } = opened.body
  assert.match((await api('GET', view)).body.toString(), /Live view/)
  const person = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${view}/drive`, { headers })
  const page = person.contexts()[0].pages()[0]
  await page.waitForURL(/\/login$/)
  await page.fill('#user', 'ann')
  await page.fill('#password', 'secret')
  await page.click('button')
  await page.waitForSelector('text=Welcome ann')
  await person.close()

  const closed = await api('DELETE', `/sessions/${id}`)
  assert.equal(closed.status, 200)
  signedIn = closed.body.state
  assert.ok(signedIn.cookies.find((c: any) => c.name === 'sid'))
  assert.deepEqual(signedIn.origins[0].localStorage, [{ name: 'portal-pref', value: 'dense' }])
  assert.ok(closed.body.log.find((e: any) => e.method === 'POST' && e.url.endsWith('/login') && e.status === 303 && e.live))
  assert.equal(leftovers(), '')
})

test('an agent works with the saved login inside the site rules', async () => {
  const opened = await api('POST', '/sessions', { kind: 'browser', site, state: signedIn })
  assert.equal(opened.status, 201)
  const { id, cdp } = opened.body
  const agent = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${cdp}`, { headers })
  const page = agent.contexts()[0].pages()[0]
  await page.waitForSelector('text=Welcome ann')

  const report = await page.evaluate(() => fetch('/report', { method: 'POST', body: '{}' }).then(r => r.json()))
  assert.deepEqual(report, { user: 'ann', rows: [['cash', 100]] })
  const write = await page.evaluate(() => fetch('/update', { method: 'POST', body: 'amount=2' }).then(r => r.status))
  assert.equal(write, 403)

  const [download] = await Promise.all([page.waitForEvent('download'), page.click('#download')])
  const file = await api('GET', `/sessions/${id}/files${await download.path()}`)
  assert.equal(file.body.toString(), 'account,amount\ncash,100\n')
  const put = await api('PUT', `/sessions/${id}/files/tmp/in/hello.txt`, 'hi')
  assert.equal(put.status, 204)
  assert.equal((await api('GET', `/sessions/${id}/files/tmp/in/hello.txt`)).body.toString(), 'hi')
  assert.equal((await api('GET', `/sessions/${id}/files/tmp/nothing`)).status, 404)

  await page.click('#other')
  assert.match(await page.textContent('body') ?? '', /host not on the list/)
  await page.goto(site.start_url)
  await page.click('#update button')
  assert.match(await page.textContent('body') ?? '', /writes are off/)
  assert.deepEqual(portal.writes, [])

  const shot = await api('GET', `/sessions/${id}/screenshot`)
  assert.deepEqual([...shot.body.subarray(1, 4)], [...Buffer.from('PNG')])
  await agent.close()

  const log = (await api('GET', `/sessions/${id}/log`)).body
  const find = (method: string, path: string) => log.find((e: any) => e.method === method && new URL(e.url).pathname === path)
  assert.equal(find('POST', '/report').status, 200)
  assert.equal(find('POST', '/update').blocked, 'writes are off')
  assert.equal(find('GET', '/download').status, 200)
  assert.equal(log.find((e: any) => new URL(e.url).hostname === 'other.localhost').blocked, 'host not on the list')

  const closed = await api('DELETE', `/sessions/${id}`)
  const sid = (state: any) => state.cookies.find((c: any) => c.name === 'sid').value
  assert.notEqual(sid(closed.body.state), sid(signedIn))
  assert.ok(portal.sessions.has(sid(closed.body.state)))
  assert.ok(!portal.sessions.has(sid(signedIn)))
  assert.equal(leftovers(), '')
})

test('hosts matched by a wildcard may not reach internal addresses', async () => {
  const { body } = await api('POST', '/sessions', { kind: 'browser', site: { ...site, hosts: ['portal.localhost', '*.portal.localhost'] } })
  const agent = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${body.cdp}`, { headers })
  const page = agent.contexts()[0].pages()[0]
  const res = await page.goto(`https://sub.portal.localhost:${portal.port()}/`)
  assert.equal(res!.status(), 502)
  assert.match(await page.textContent('body') ?? '', /resolves only to internal addresses/)
  await agent.close()
  await api('DELETE', `/sessions/${body.id}`)
})

test('a session past its ttl is closed and keeps its result until collected', async () => {
  const { body } = await api('POST', '/sessions', { kind: 'browser', site, state: signedIn, ttl_s: 1 })
  await new Promise(r => setTimeout(r, 2500))
  assert.equal((await api('GET', `/sessions/${body.id}/screenshot`)).status, 410)
  assert.equal((await api('GET', `/sessions/${body.id}/log`)).status, 200)
  assert.equal(leftovers(), '')
  const closed = await api('DELETE', `/sessions/${body.id}`)
  assert.ok(closed.body.state.cookies.length)
  assert.equal((await api('DELETE', `/sessions/${body.id}`)).status, 404)
})
