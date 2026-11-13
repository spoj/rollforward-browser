import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, execFileSync, type ChildProcess } from 'node:child_process'
import { once } from 'node:events'
import fs from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import dns from 'node:dns/promises'
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
  fs.writeFileSync(`${tmp}/san`, 'subjectAltName=DNS:portal.localhost,DNS:other.localhost,DNS:sub.portal.localhost,DNS:public.example,DNS:portal.via.invalid,DNS:sub.branch.via.invalid,IP:127.0.0.1\n')
  openssl('x509', '-req', '-in', 'portal.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '1', '-extfile', 'san', '-out', 'portal.pem')
  portal = startPortal({ key: fs.readFileSync(`${tmp}/portal.key`, 'utf8'), cert: fs.readFileSync(`${tmp}/portal.pem`, 'utf8') })
  await once(portal.server, 'listening')
  const origin = `https://portal.localhost:${portal.port()}`
  site = { hosts: ['portal.localhost'], start_url: `${origin}/` }
  const ready = new Promise<void>(r => releaseLists = r)
  lists = http.createServer(async (_req, res) => {
    await ready
    res.end('# test threats\n\nblocked.example\nother.localhost\nxn--bcher-kva.example\n')
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

test('blocklists load without delaying ordinary sessions, then /blocked checks a domain and its parents, an IDN as the proxy sees it', async () => {
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
    result = await api('GET', '/blocked?host=blocked.example&host=sub.blocked.example&host=other.example&host=notblocked.example&host=BLOCKED.EXAMPLE.&host=sub.bücher.example')
  } while (result.status === 503)
  assert.deepEqual(result, { status: 200, body: { 'blocked.example': true, 'sub.blocked.example': true, 'other.example': false, 'notblocked.example': false, 'BLOCKED.EXAMPLE.': true, 'sub.bücher.example': true } })
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

test('via hosts tunnel through an http or https proxy without local DNS, with a bearer token held only by the service; other hosts stay direct', async t => {
  await assert.rejects(dns.lookup('portal.via.invalid'), { code: 'ENOTFOUND' })
  const plain = http.createServer(portal.server.listeners('request')[0] as http.RequestListener).listen(0, '127.0.0.1')
  plain.on('upgrade', portal.server.listeners('upgrade')[0] as any)
  t.after(() => plain.close())
  await once(plain, 'listening')
  const plainPort = (plain.address() as net.AddressInfo).port
  for (const secure of [false, true]) {
    const token = `via-secret-${secure}`, asked: string[] = [], sockets = new Set<net.Socket>()
    const proxy = secure ? https.createServer({ key: fs.readFileSync(`${tmp}/portal.key`), cert: fs.readFileSync(`${tmp}/portal.pem`) }) : http.createServer()
    proxy.on('connection', socket => {
      sockets.add(socket)
      socket.on('close', () => sockets.delete(socket))
    })
    proxy.on('connect', (req, socket, head) => {
      asked.push(req.url!)
      if (req.headers['proxy-authorization'] !== `Bearer ${token}`) return socket.end('HTTP/1.1 407 Proxy Authentication Required\r\n\r\n')
      const up = net.connect(Number(new URL(`http://${req.url}`).port), '127.0.0.1', () => {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
        up.write(head)
        socket.pipe(up).pipe(socket)
      })
      socket.on('error', () => up.destroy())
      socket.on('close', () => up.destroy())
      up.on('error', () => socket.destroy())
    })
    proxy.listen(0, '127.0.0.1')
    await once(proxy, 'listening')
    t.after(() => proxy.close())
    const via = { url: `${secure ? 'https' : 'http'}://127.0.0.1:${(proxy.address() as net.AddressInfo).port}`, token, hosts: ['PORTAL.via.invalid', '*.BRANCH.via.invalid', 'denied.example', 'blocked.example'] }
    const opened = await api('POST', '/sessions', { site: { hosts: ['*.via.invalid', 'other.localhost'], via } })
    assert.equal(opened.status, 201)
    const { id, cdp, view } = opened.body
    const agent = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${cdp}`, { headers })
    const page = agent.contexts()[0].pages()[0], seen: string[] = []
    page.on('request', r => seen.push(JSON.stringify(r.headers())))
    for (const host of ['portal.via.invalid', 'sub.branch.via.invalid']) {
      assert.equal((await page.goto(`https://${host}:${portal.port()}/login`))!.status(), 200)
      assert.ok(asked.includes(`${host}:${portal.port()}`))
    }
    assert.equal(await page.evaluate(() => new Promise(resolve => { new WebSocket(`wss://${location.host}/ws`).onmessage = e => resolve(e.data) })), 'hello')
    assert.equal((await page.goto(`http://portal.via.invalid:${plainPort}/login`))!.status(), 200)
    assert.equal(await page.evaluate(() => new Promise(resolve => { new WebSocket(`ws://${location.host}/ws`).onmessage = e => resolve(e.data) })), 'hello')
    assert.ok(asked.includes(`portal.via.invalid:${plainPort}`))
    const before = asked.length
    assert.equal((await page.goto(`https://other.localhost:${portal.port()}/`))!.status(), 200)
    assert.equal(asked.length, before, 'non-via hosts stay direct')
    assert.equal((await api('PUT', `/sessions/${id}/hosts`, { hosts: ['other.localhost'] })).status, 200)
    assert.equal((await page.goto(`https://portal.via.invalid:${portal.port()}/login`))!.status(), 403, 'a via route grants no host permission, even on a pooled connection')
    assert.equal(asked.length, before)
    assert.ok(!seen.join('').includes(token))
    for (const path of ['/sessions', '/drained', '/blocked?host=portal.via.invalid', `${view}`, `/sessions/${id}/log`, `/sessions/${id}/page`]) assert.ok(!JSON.stringify((await api('GET', path)).body).includes(token), path)
    await agent.close()
    const closed = await api('DELETE', `/sessions/${id}`)
    assert.ok(closed.body.log.some((e: any) => e.status === 101))
    assert.ok(!JSON.stringify([opened, closed]).includes(token))

    for (const [open, publicSite] of [[true, false], [false, true]]) {
      const own = await api('POST', '/sessions', { site: { hosts: publicSite ? ['*.via.invalid'] : [], open, public: publicSite, except: ['denied.example'], via } })
      const browser = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${own.body.cdp}`, { headers })
      const tab = browser.contexts()[0].pages()[0]
      assert.equal((await tab.goto(`https://portal.via.invalid:${portal.port()}/login`))!.status(), 200, 'via works for unlisted open hosts and listed public hosts')
      if (open) assert.equal((await tab.goto(`https://portal.via.invalid.:${portal.port()}/login`))!.status(), 200, 'a trailing dot still goes through via, never resolved here')
      for (const url of [`http://portal.via.invalid:${plainPort}/login`, 'https://denied.example/', 'https://blocked.example/']) assert.equal((await tab.goto(url))!.status(), 403)
      await browser.close()
      const result = await api('DELETE', `/sessions/${own.body.id}`)
      assert.ok(!JSON.stringify([own, result]).includes(token))
    }

    const wrong = await api('POST', '/sessions', { site: { hosts: ['portal.via.invalid'], via: { ...via, token: 'wrong-secret' } } })
    const browser = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${wrong.body.cdp}`, { headers })
    assert.equal((await browser.contexts()[0].pages()[0].goto(`https://portal.via.invalid:${portal.port()}/login`))!.status(), 502)
    await browser.close()
    const result = await api('DELETE', `/sessions/${wrong.body.id}`)
    assert.match(result.body.log.find((e: any) => e.status === 502).error, /upstream proxy CONNECT: 407/)
    assert.ok(!JSON.stringify([wrong, result]).includes('wrong-secret'))
    proxy.close()
    for (const socket of sockets) socket.destroy()
    const down = await api('POST', '/sessions', { site: { hosts: ['portal.via.invalid'], via } })
    const last = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${down.body.cdp}`, { headers })
    assert.equal((await last.contexts()[0].pages()[0].goto(`https://portal.via.invalid:${portal.port()}/login`))!.status(), 502)
    await last.close()
    const failed = await api('DELETE', `/sessions/${down.body.id}`)
    assert.match(failed.body.log.find((e: any) => e.status === 502).error, /ECONNREFUSED/)
    assert.ok(!JSON.stringify([down, failed]).includes(token))
  }
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

test('an IP literal listed exactly reaches no loopback, link-local or WireServer address, nor, for a public site, an internal one', async () => {
  const here = Object.values(os.networkInterfaces()).flat().find(a => a!.family === 'IPv4' && !a!.internal)!.address
  for (const [publicSite, hosts] of [[false, ['127.0.0.1', '[::1]', '169.254.169.254', '168.63.129.16']], [true, [here]]] as const) {
    const { body } = await api('POST', '/sessions', { site: { hosts, public: publicSite } })
    const agent = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${body.cdp}`, { headers })
    const page = agent.contexts()[0].pages()[0]
    for (const host of hosts) {
      assert.equal((await page.goto(`https://${host}:${portal.port()}/login`))!.status(), 403, host)
      assert.match(await page.textContent('body') ?? '', /internal address/)
    }
    await agent.close()
    await api('DELETE', `/sessions/${body.id}`)
  }
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

test("a site whose lists or headers the proxy couldn't use is a 400, never reaching the proxy, where it would end every client's sessions", async () => {
  const via = { url: 'http://127.0.0.1:1', token: 'via-secret', hosts: [] }
  for (const bad of [{ hosts: 'portal.localhost' }, { hosts: [1] }, { hosts: ['bücher.example'] }, { hosts: ['portal.localhost.'] }, { hosts: [], open: true, except: 'a.example' },
    { hosts: [], via: { ...via, hosts: undefined } }, { hosts: [], via: { ...via, token: 'via-secret\r\nx: y' } }, { hosts: [], headers: { 'x-bot-token': 'a\nb' } }, { hosts: [], headers: { 'a b': 'c' } }]) {
    const res = await api('POST', '/sessions', { site: bad })
    assert.equal(res.status, 400, JSON.stringify(bad))
    assert.ok(!JSON.stringify(res.body).includes('via-secret'))
  }
  assert.deepEqual((await api('GET', '/sessions')).body, [])
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
