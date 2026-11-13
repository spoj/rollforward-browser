import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, execFileSync, type ChildProcess } from 'node:child_process'
import { once } from 'node:events'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import net from 'node:net'
import { chromium } from 'playwright-core'
import { startPortal } from './portal.ts'
import { isInternal, isNever } from '../src/proxy.ts'

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
let lists: http.Server
let releaseLists: () => void
let site: { hosts: string[], start_url: string }

before(async () => {
  openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=test-ca', '-days', '1', '-keyout', 'ca.key', '-out', 'ca.pem')
  openssl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=portal.localhost', '-keyout', 'portal.key', '-out', 'portal.csr')
  fs.writeFileSync(`${tmp}/san`, 'subjectAltName=DNS:portal.localhost,DNS:other.localhost,DNS:sub.portal.localhost,DNS:public.example\n')
  openssl('x509', '-req', '-in', 'portal.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '1', '-extfile', 'san', '-out', 'portal.pem')
  portal = startPortal({ key: fs.readFileSync(`${tmp}/portal.key`, 'utf8'), cert: fs.readFileSync(`${tmp}/portal.pem`, 'utf8') })
  await once(portal.server, 'listening')
  const origin = `https://portal.localhost:${portal.port()}`
  site = { hosts: ['portal.localhost'], start_url: `${origin}/` }
  const ready = new Promise<void>(r => releaseLists = r)
  lists = http.createServer(async (_req, res) => {
    await ready
    res.end('# test threats\n\nblocked.example\nother.localhost\n')
  }).listen(0, '127.0.0.1')
  await once(lists, 'listening')
  const listUrl = `http://127.0.0.1:${(lists.address() as net.AddressInfo).port}/`
  service = spawn('node', ['--import', './test/resolve.ts', 'src/server.ts'], { env: { ...process.env, BROWSER_PORT: String(port), BROWSER_KEY: key, BROWSER_BLOCKLISTS: listUrl, NODE_EXTRA_CA_CERTS: `${tmp}/ca.pem` }, stdio: ['ignore', 'pipe', 'inherit'] })
  await Promise.race([once(service.stdout!, 'data'), once(service, 'exit').then(() => { throw new Error('service exited') })])
})

after(() => {
  service.kill()
  portal.server.close()
  lists.close()
  fs.rmSync(tmp, { recursive: true })
})

const leftovers = () => execFileSync('podman', ['ps', '-a', '-q', '--filter', `label=rollforward-browser=${port}`]).toString().trim() + fs.readdirSync(`${os.tmpdir()}/rollforward-browser-${port}`).join(' ')

let signedIn: any

test('blocklists load without delaying ordinary sessions, then /blocked checks a domain and its parents', async () => {
  const waiting = await api('GET', '/blocked?host=blocked.example')
  assert.deepEqual(waiting, { status: 503, body: { error: 'blocklists not loaded yet' } })
  assert.deepEqual(await api('POST', '/sessions', { site: { ...site, open: true } }), waiting)
  const ordinary = await api('POST', '/sessions', { site })
  assert.equal(ordinary.status, 201)
  await api('DELETE', `/sessions/${ordinary.body.id}`)
  releaseLists()
  let result
  do {
    await new Promise(r => setTimeout(r, 20))
    result = await api('GET', '/blocked?host=blocked.example&host=sub.blocked.example&host=other.example&host=notblocked.example&host=BLOCKED.EXAMPLE.')
  } while (result.status === 503)
  assert.deepEqual(result, { status: 200, body: { 'blocked.example': true, 'sub.blocked.example': true, 'other.example': false, 'notblocked.example': false, 'BLOCKED.EXAMPLE.': true } })
})

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
  assert.deepEqual(closed.body.log.filter((e: any) => new URL(e.url).hostname !== 'portal.localhost'), [], "nothing of Chromium's own, such as autofill's or its updater's, leaves the browser")
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
  const other = log.find((e: any) => new URL(e.url).hostname === 'other.localhost'), first = log.find((e: any) => e.url === site.start_url)
  assert.deepEqual([other.blocked, other.dest, other.from], ['host not on the list', 'document', site.start_url], "its kind and the page it came from, as the browser sent them: another site's carries the page's origin alone")
  assert.deepEqual([find('POST', '/report').dest, find('POST', '/report').from, first.dest, 'from' in first], ['empty', site.start_url, 'document', false], "a page's own fetch, and the first page, which no page asked for")
  assert.deepEqual([...new Set(log.filter((e: any) => e.blocked).map((e: any) => new URL(e.url).hostname))], ['other.localhost'], "only the page's own: nothing of Chromium's leaves the browser")

  const closed = await api('DELETE', `/sessions/${id}`)
  const sid = (state: any) => state.cookies.find((c: any) => c.name === 'sid').value
  assert.notEqual(sid(closed.body.state), sid(signedIn))
  assert.ok(portal.sessions.has(sid(closed.body.state)))
  assert.ok(!portal.sessions.has(sid(signedIn)))
  assert.equal(leftovers(), '')
})

test("a site's headers go with requests to start_url's origin alone, added by the proxy, never in the browser or the log", async () => {
  const { body } = await api('POST', '/sessions', { site: { ...site, hosts: ['portal.localhost', 'other.localhost'], except: ['other.localhost'], headers: { 'x-bot-token': 'jwt-1' } } })
  const agent = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${body.cdp}`, { headers })
  const page = agent.contexts()[0].pages()[0], seen: string[] = []
  page.on('request', r => seen.push(JSON.stringify(r.headers())))
  portal.tokens.length = 0
  await page.goto(`${site.start_url}login`)
  await page.goto(`https://other.localhost:${portal.port()}/`)
  assert.deepEqual([...new Set(portal.tokens)], ['portal.localhost jwt-1', 'other.localhost -'])
  assert.ok(seen.length && !seen.some(h => h.includes('jwt-1')), 'the browser never holds them')
  await agent.close()
  const { log } = (await api('DELETE', `/sessions/${body.id}`)).body
  assert.ok(log.length && !JSON.stringify(log).includes('jwt-1'))
})

test('pages see a browser without passkeys, in its first tab and any tab an agent opens, so a sign-in never waits on one', async () => {
  const { body } = await api('POST', '/sessions', { site })
  const agent = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${body.cdp}`, { headers })
  const ctx = agent.contexts()[0]
  for (const page of [ctx.pages()[0], await ctx.newPage()]) {
    await page.goto(`${site.start_url}login`)
    const seen = await page.evaluate(async () => {
      const ask = (how: 'get' | 'create') => navigator.credentials[how]({ publicKey: {} } as any).then(() => 'answered', e => e.name)
      return [typeof (window as any).PublicKeyCredential, await ask('get'), await ask('create')]
    })
    assert.deepEqual(seen, ['undefined', 'NotAllowedError', 'NotAllowedError'])
  }
  await agent.close()
  await api('DELETE', `/sessions/${body.id}`)
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

test("a person's own site reaches no internal address, not even by an exact host; and a session's hosts grow as hosts are allowed", async () => {
  for (const open of [false, true]) {
    const own = await api('POST', '/sessions', { site: { ...site, start_url: undefined, public: true, open } })
    const agent = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${own.body.cdp}`, { headers })
    const res = await agent.contexts()[0].pages()[0].goto(`https://portal.localhost:${portal.port()}/`)
    assert.equal(res!.status(), 502)
    await agent.close()
    await api('DELETE', `/sessions/${own.body.id}`)
  }
  const { body } = await api('POST', '/sessions', { site: { ...site, start_url: undefined } })
  const agent = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${body.cdp}`, { headers })
  const page = agent.contexts()[0].pages()[0], other = `https://other.localhost:${portal.port()}/`
  assert.equal((await page.goto(other))!.status(), 403)
  assert.deepEqual((await api('PUT', `/sessions/${body.id}/hosts`, { hosts: ['portal.localhost', 'other.localhost'] })).body, { hosts: ['portal.localhost', 'other.localhost'] })
  assert.equal((await page.goto(other))!.status(), 200)
  const again = page.waitForEvent('load')
  assert.equal((await api('POST', `/sessions/${body.id}/reload`)).status, 200)
  await again
  assert.equal((await api('PUT', `/sessions/${body.id}/hosts`, { hosts: ['bad host'] })).status, 400)
  await agent.close()
  await api('DELETE', `/sessions/${body.id}`)
})

test('an open sign-in reaches unlisted public hosts over https, but not threats, exceptions, IP literals or unlisted internal hosts', async () => {
  const opened = await api('POST', '/sessions', { site: { ...site, open: true, hosts: ['portal.localhost', 'blocked.example', 'other.localhost', 'sub.denied.example'], except: ['OTHER.localhost', '*.denied.example', '*.public.example'] }, ttl_s: 60 })
  assert.equal(opened.status, 201, 'an exact host of a non-public site keeps its intranet access')
  const { id, cdp } = opened.body
  const agent = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${cdp}`, { headers })
  const page = agent.contexts()[0].pages()[0]
  assert.equal((await page.goto(`https://public.example:${portal.port()}/login`))!.status(), 200)
  for (const [url, reason] of [
    [`http://public.example:${portal.port()}/login`, 'https only'],
    ['https://blocked.example/', 'on a blocklist'],
    ['https://sub.blocked.example/', 'on a blocklist'],
    ['https://BLOCKED.EXAMPLE./', 'on a blocklist'],
    [`https://other.localhost:${portal.port()}/`, 'host not on the list'],
    ['https://sub.denied.example/', 'host not on the list'],
    ['https://sub.denied.example./', 'host not on the list'],
    ['https://8.8.8.8/', 'host not on the list'],
    ['https://[::1]/', 'host not on the list'],
  ]) {
    assert.equal((await page.goto(url))!.status(), 403, url)
    assert.match(await page.textContent('body') ?? '', new RegExp(reason))
  }
  assert.equal((await page.goto(`https://sub.portal.localhost:${portal.port()}/`))!.status(), 502)
  assert.match(await page.textContent('body') ?? '', /resolves only to internal addresses/)
  assert.equal((await api('PUT', `/sessions/${id}/hosts`, { hosts: ['other.localhost', 'sub.portal.localhost'] })).status, 200)
  assert.equal((await page.goto(`https://sub.portal.localhost:${portal.port()}/login`))!.status(), 200, 'an exact host added with PUT keeps its intranet access')
  assert.equal((await page.goto(`https://other.localhost:${portal.port()}/`))!.status(), 403, 'PUT cannot override except')
  assert.equal((await api('PUT', `/sessions/${id}/hosts`, { hosts: [] })).status, 200)
  assert.equal((await page.goto(`https://sub.portal.localhost:${portal.port()}/login?removed`))!.status(), 502, 'removing an exact host cannot reuse its intranet connection')
  await agent.close()
  const { log } = (await api('DELETE', `/sessions/${id}`)).body
  assert.ok(log.some((e: any) => e.url.startsWith('https://public.example:') && e.status === 200))
  assert.equal(log.find((e: any) => e.url.startsWith('http://public.example:')).blocked, 'https only')
  for (const host of ['blocked.example', 'sub.blocked.example']) assert.equal(log.find((e: any) => new URL(e.url).hostname === host).blocked, 'on a blocklist')
  for (const host of ['other.localhost', 'sub.denied.example', '8.8.8.8', '[::1]']) assert.equal(log.find((e: any) => new URL(e.url).hostname === host).blocked, 'host not on the list')
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

test('a page says where the newest tab is and whether it shows a password field, as a sign-in does', async () => {
  const { id, cdp } = (await api('POST', '/sessions', { site })).body
  const page = await api('GET', `/sessions/${id}/page`)
  const agent = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${cdp}`, { headers }), tab = agent.contexts()[0].pages()[0]
  await tab.fill('#user', 'ann')
  await tab.fill('#password', 'secret')
  await tab.click('button')
  await tab.waitForSelector('text=Welcome ann')
  await agent.close()
  const after = await api('GET', `/sessions/${id}/page`)
  await api('DELETE', `/sessions/${id}`)
  assert.deepEqual(page.body, { url: `${site.start_url}login`, password: true }, 'signed out: the sign-in page')
  assert.deepEqual(after.body, { url: site.start_url, password: false }, 'signed in: the page itself')
})

test('the live view shows the browser and, once the person takes control or opens it with ?drive, passes their input', async t => {
  const { body } = await api('POST', '/sessions', { site })
  const agent = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${body.cdp}`, { headers })
  const page = agent.contexts()[0].pages()[0]
  await page.waitForURL(/\/login$/)
  const width = await page.evaluate(() => innerWidth)

  const person = await chromium.launch()
  t.after(() => person.close())
  const signIn = await (await person.newContext({ extraHTTPHeaders: headers })).newPage()
  await signIn.goto(`http://127.0.0.1:${port}${body.view}?drive`)
  await signIn.waitForFunction(() => document.title.includes('you have control'))
  await signIn.close()
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

test("a watcher asks only for the tabs and a screencast of one: anything else, such as a script or a CDP client's own setup, ends its socket", async () => {
  const { body } = await api('POST', '/sessions', { site })
  await assert.rejects(chromium.connectOverCDP(`ws://127.0.0.1:${port}${body.view}/watch`, { headers, timeout: 5000 }))
  const ws = new WebSocket(`ws://127.0.0.1:${port}${body.view}/watch`, { headers } as never), got: { id?: number }[] = []
  ws.onmessage = e => got.push(JSON.parse(e.data))
  await once(ws, 'open')
  ws.send(JSON.stringify({ id: 1, method: 'Target.setDiscoverTargets', params: { discover: true } }))
  while (!got.some(m => m.id === 1)) await new Promise(r => setTimeout(r, 50))
  ws.send(JSON.stringify({ id: 2, method: 'Runtime.evaluate', params: { expression: 'location.href = "https://example.com"' } }))
  await once(ws, 'close')
  assert.ok(!got.some(m => m.id === 2), 'it never reached the browser')
  await api('DELETE', `/sessions/${body.id}`)
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

// Last: a drained service opens no more sessions.
test('an update drains the service: no session opens, and /drained answers once every session has been collected', async () => {
  const { body } = await api('POST', '/sessions', { site })
  assert.equal((await api('GET', '/drained')).status, 503, 'no drain asked')
  service.kill('SIGUSR2')
  await new Promise(r => setTimeout(r, 200))
  const refused = await api('POST', '/sessions', { site })
  assert.deepEqual([refused.status, refused.body.error], [503, 'updating: try again in a few minutes'])
  assert.equal((await api('GET', `/sessions/${body.id}/screenshot`)).status, 200, 'the open one carries on')
  assert.equal((await api('GET', '/drained')).status, 503, 'one is still open')
  assert.ok((await api('DELETE', `/sessions/${body.id}`)).body.log.length, 'its log is collected')
  assert.equal((await api('GET', '/drained')).status, 200)
})

test("internal addresses are the private ranges, an IPv4-mapped answer by its IPv4 part, and public IPv4 isn't one", () => {
  for (const a of ['8.8.8.8', '184.24.154.186']) assert.equal(isInternal(a, 4), false)
  for (const a of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.0.1', '169.254.1.1', '100.64.0.1']) assert.equal(isInternal(a, 4), true)
  assert.equal(isInternal('::ffff:127.0.0.1', 6), true)
  assert.equal(isInternal('::ffff:8.8.8.8', 6), false)
  assert.equal(isInternal('168.63.129.16', 4), true, "Azure's WireServer")
  for (const a of ['169.254.169.254', '168.63.129.16', '0.0.0.0']) assert.equal(isNever(a, 4), true, `${a}, not even for an exact host`)
  for (const [a, f] of [['::ffff:169.254.169.254', 6], ['fe80::1', 6]] as const) assert.equal(isNever(a, f), true, a)
  for (const a of ['127.0.0.1', '127.1.2.3']) assert.equal(isNever(a, 4), true, `${a}, this machine's own`)
  for (const [a, f] of [['::1', 6], ['::ffff:127.0.0.1', 6]] as const) assert.equal(isNever(a, f), true, a)
  for (const a of ['10.1.2.3', '192.168.0.1', '8.8.8.8']) assert.equal(isNever(a, 4), false, `${a}, an intranet's or the internet's`)
  for (const a of ['::1', '::', 'fc00::1', 'fe80::1']) assert.equal(isInternal(a, 6), true)
  assert.equal(isInternal('2a04:4e42:68::347', 6), false)
})
