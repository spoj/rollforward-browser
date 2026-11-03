import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, execFileSync, type ChildProcess } from 'node:child_process'
import { once } from 'node:events'
import fs from 'node:fs'
import os from 'node:os'
import net from 'node:net'
import { chromium } from 'playwright-core'
import { startPortal } from './portal.ts'

const port = 8798
const key = 'test-key'
const headers = { authorization: `Bearer ${key}` }
const api = async (method: string, path: string, body?: unknown) => {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers, body: typeof body === 'string' || body === undefined ? body : JSON.stringify(body) })
  return { status: res.status, body: res.headers.get('content-type') === 'application/json' ? await res.json() : Buffer.from(await res.arrayBuffer()) }
}
const tmp = fs.mkdtempSync(`${os.tmpdir()}/rollforward-browser-test-`)
const openssl = (...args: string[]) => execFileSync('openssl', args, { cwd: tmp, stdio: 'ignore' })
let portal: ReturnType<typeof startPortal>
let service: ChildProcess
let site: { hosts: string[], start_url: string }

before(async () => {
  openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=test-ca', '-days', '1', '-keyout', 'ca.key', '-out', 'ca.pem')
  openssl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=portal.localhost', '-keyout', 'portal.key', '-out', 'portal.csr')
  fs.writeFileSync(`${tmp}/san`, 'subjectAltName=DNS:portal.localhost,DNS:other.localhost,DNS:sub.portal.localhost\n')
  openssl('x509', '-req', '-in', 'portal.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '1', '-extfile', 'san', '-out', 'portal.pem')
  portal = startPortal({ key: fs.readFileSync(`${tmp}/portal.key`, 'utf8'), cert: fs.readFileSync(`${tmp}/portal.pem`, 'utf8') })
  await once(portal.server, 'listening')
  const origin = `https://portal.localhost:${portal.port()}`
  site = { hosts: ['portal.localhost'], start_url: `${origin}/` }
  service = spawn('node', ['src/server.ts'], { env: { ...process.env, BROWSER_PORT: String(port), BROWSER_KEY: key, NODE_EXTRA_CA_CERTS: `${tmp}/ca.pem` }, stdio: ['ignore', 'pipe', 'inherit'] })
  await Promise.race([once(service.stdout!, 'data'), once(service, 'exit').then(() => { throw new Error('service exited') })])
})

after(() => {
  service.kill()
  portal.server.close()
  fs.rmSync(tmp, { recursive: true })
})

const leftovers = () => execFileSync('podman', ['ps', '-a', '-q', '--filter', `label=rollforward-browser=${port}`]).toString().trim() + fs.readdirSync(`${os.tmpdir()}/rollforward-browser-${port}`).join(' ')

let signedIn: any

test('a person signs in through the live view; closing returns the login', async () => {
  const opened = await api('POST', '/sessions', { site })
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

test("an agent works with the saved login on the site's hosts, and every request is logged", async () => {
  const opened = await api('POST', '/sessions', { site, state: signedIn })
  assert.equal(opened.status, 201)
  const { id, cdp } = opened.body
  const agent = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${cdp}`, { headers })
  const page = agent.contexts()[0].pages()[0]
  await page.waitForSelector('text=Welcome ann')

  const report = await page.evaluate(() => fetch('/report', { method: 'POST', body: '{}' }).then(r => r.json()))
  assert.deepEqual(report, { user: 'ann', rows: [['cash', 100]] })
  const write = await page.evaluate(() => fetch('/update', { method: 'POST', body: 'amount=2' }).then(r => r.status))
  assert.equal(write, 200)

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
  assert.deepEqual(portal.writes, ['amount=2'])

  const message = await page.evaluate(() => new Promise(resolve => { new WebSocket(`wss://${location.host}/ws`).onmessage = e => resolve(e.data) }))
  assert.equal(message, 'hello')

  const shot = await api('GET', `/sessions/${id}/screenshot`)
  assert.deepEqual([...shot.body.subarray(1, 4)], [...Buffer.from('PNG')])
  await agent.close()

  const log = (await api('GET', `/sessions/${id}/log`)).body
  const find = (method: string, path: string) => log.find((e: any) => e.method === method && new URL(e.url).pathname === path)
  assert.equal(find('POST', '/report').status, 200)
  assert.equal(find('POST', '/update').status, 200)
  assert.ok(!log.some((e: any) => e.live), 'no person drove it')
  assert.equal(find('GET', '/download').status, 200)
  assert.equal(find('GET', '/ws').status, 101)
  assert.equal(log.find((e: any) => new URL(e.url).hostname === 'other.localhost').blocked, 'host not on the list')

  const closed = await api('DELETE', `/sessions/${id}`)
  const sid = (state: any) => state.cookies.find((c: any) => c.name === 'sid').value
  assert.notEqual(sid(closed.body.state), sid(signedIn))
  assert.ok(portal.sessions.has(sid(closed.body.state)))
  assert.ok(!portal.sessions.has(sid(signedIn)))
  assert.equal(leftovers(), '')
})

test('hosts matched by a wildcard may not reach internal addresses', async () => {
  const { body } = await api('POST', '/sessions', { site: { ...site, hosts: ['portal.localhost', '*.portal.localhost'] } })
  const agent = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${body.cdp}`, { headers })
  const page = agent.contexts()[0].pages()[0]
  const res = await page.goto(`https://sub.portal.localhost:${portal.port()}/`)
  assert.equal(res!.status(), 502)
  assert.match(await page.textContent('body') ?? '', /resolves only to internal addresses/)
  await agent.close()
  await api('DELETE', `/sessions/${body.id}`)
})

test('malformed requests to the proxy get a 403 and are logged', async () => {
  const { body } = await api('POST', '/sessions', { site })
  const ask = async (raw: string) => {
    const s = net.connect(`${os.tmpdir()}/rollforward-browser-${port}/${body.id}/proxy.sock`)
    s.end(raw)
    return Buffer.concat(await s.toArray()).toString()
  }
  assert.match(await ask('GET /relative HTTP/1.1\r\nhost: portal.localhost\r\n\r\n'), /403[^]*malformed request/)
  assert.match(await ask('CONNECT portal.localhost:443 HTTP/1.1\r\n\r\nGET http://other.localhost/ HTTP/1.1\r\nhost: x\r\n\r\n'), /200 Connection Established[^]*403[^]*malformed request/)
  assert.match(await ask('CONNECT a:b:c HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\nhost: x\r\n\r\n'), /403[^]*malformed request/)
  const { body: log } = await api('GET', `/sessions/${body.id}/log`)
  assert.equal(log.filter((e: any) => e.blocked === 'malformed request').length, 3)
  await api('DELETE', `/sessions/${body.id}`)
})

test('the live view shows the browser and, once the person takes control, passes their input', async t => {
  const { body } = await api('POST', '/sessions', { site })
  const agent = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${body.cdp}`, { headers })
  const page = agent.contexts()[0].pages()[0]
  await page.waitForURL(/\/login$/)
  const width = await page.evaluate(() => innerWidth)

  const person = await chromium.launch()
  t.after(() => person.close())
  const view = await (await person.newContext({ extraHTTPHeaders: headers })).newPage()
  await view.goto(`http://127.0.0.1:${port}${body.view}`)
  await view.waitForFunction(() => (document.getElementById('img') as HTMLImageElement).src.startsWith('data:image/jpeg'))
  const click = async (selector: string) => {
    const box = (await page.locator(selector).boundingBox())!
    const img = (await view.locator('#img').boundingBox())!
    const scale = img.width / width
    await view.mouse.click(img.x + (box.x + box.width / 2) * scale, img.y + (box.y + box.height / 2) * scale)
  }
  await click('#user')
  await view.keyboard.type('bob')
  assert.equal(await page.inputValue('#user'), '', 'watching passes no input')
  assert.notEqual(await view.evaluate(() => document.activeElement!.id), 'kb', 'watching opens no keyboard')

  await view.click('#drive')
  await view.waitForFunction(() => document.title.includes('you have control'))
  await click('#user')
  assert.equal(await view.evaluate(() => document.activeElement!.id), 'kb', 'a tap opens the keyboard')
  await view.keyboard.insertText('bobb')
  await view.evaluate(() => {
    const kb = document.getElementById('kb') as HTMLInputElement
    kb.value = kb.value.slice(0, -1)
    kb.dispatchEvent(new Event('input'))
  })
  await click('#password')
  await view.keyboard.type('secret')
  await view.keyboard.press('Enter')
  await page.waitForSelector('text=Welcome bob')
  await agent.close()
  const closed = await api('DELETE', `/sessions/${body.id}`)
  assert.ok(closed.body.log.find((e: any) => e.method === 'POST' && e.url.endsWith('/login') && e.live))
})

test('a session past its ttl is closed and keeps its result until collected', async () => {
  const { body } = await api('POST', '/sessions', { site, state: signedIn, ttl_s: 1 })
  await new Promise(r => setTimeout(r, 2500))
  assert.equal((await api('GET', `/sessions/${body.id}/screenshot`)).status, 410)
  assert.equal((await api('GET', `/sessions/${body.id}/log`)).status, 200)
  assert.equal(leftovers(), '')
  const closed = await api('DELETE', `/sessions/${body.id}`)
  assert.ok(closed.body.state.cookies.length)
  assert.equal((await api('DELETE', `/sessions/${body.id}`)).status, 404)
})
