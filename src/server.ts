import http from 'node:http'
import net from 'node:net'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import { BrowserSession, podman } from './browser.ts'

const port = Number(process.env.BROWSER_PORT ?? 8797)
const host = process.env.BROWSER_HOST ?? '127.0.0.1'
const key = process.env.BROWSER_KEY
if (!key) throw new Error('BROWSER_KEY is not set')
const runDir = `${os.tmpdir()}/rollforward-browser-${port}`
const label = `rollforward-browser=${port}`
const viewPage = fs.readFileSync(new URL('view.html', import.meta.url))

type Result = { state: unknown, log: unknown[] }
type Session = BrowserSession & { expires?: number, timer?: NodeJS.Timeout, closing?: Promise<Result> }
const sessions = new Map<string, Session>()
// An update (scripts/update.ts) drains the service before it moves the checkout: no session opens, and once every session has been
// collected with DELETE, its request log with it, or 30 minutes have passed, GET /drained answers 200, for the update to move it and
// restart the service.
let drainUntil = 0
process.on('SIGUSR2', () => { drainUntil ||= Date.now() + 30 * 60_000 })

const fail = (status: number, message: string) => Object.assign(new Error(message), { status })
const json = (res: http.ServerResponse, status: number, body: unknown) =>
  res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body))
const body = async (req: http.IncomingMessage) => Buffer.concat(await req.toArray())
const close = (s: Session) => {
  clearTimeout(s.timer)
  return s.closing ??= s.close()
}

async function open(spec: any) {
  const id = crypto.randomBytes(8).toString('hex')
  const s: Session = new BrowserSession(id, `${runDir}/${id}`, label, spec.site)
  sessions.set(id, s)
  try {
    await s.start(spec.state, `ws://${host}:${port}/sessions/${id}/cdp`, { authorization: `Bearer ${key}` })
  } catch (e) {
    sessions.delete(id)
    await close(s)
    throw e
  }
  const ttl = (spec.ttl_s ?? 3600) * 1000
  s.expires = Date.now() + ttl
  s.timer = setTimeout(() => close(s).catch(e => console.error(`closing ${id}:`, e)), ttl)
  return { id, cdp: `/sessions/${id}/cdp`, view: `/sessions/${id}/view` }
}

async function route(req: http.IncomingMessage, res: http.ServerResponse) {
  if (req.headers.authorization !== `Bearer ${key}`) throw fail(401, 'bad key')
  const { pathname } = new URL(req.url!, 'http://x')
  if (pathname === '/drained' && req.method === 'GET') return json(res, drainUntil && (!sessions.size || Date.now() > drainUntil) ? 200 : 503, { open: sessions.size })
  if (pathname === '/sessions' && req.method === 'POST' && drainUntil) throw fail(503, 'updating: try again in a few minutes')
  if (pathname === '/sessions' && req.method === 'POST') return json(res, 201, await open(JSON.parse((await body(req)).toString())))
  if (pathname === '/sessions' && req.method === 'GET') return json(res, 200, [...sessions.values()].map(s => ({ id: s.id, expires: s.expires, closed: !!s.closing })))
  const [, id, rest] = pathname.match(/^\/sessions\/([^/]+)(.*)$/) ?? []
  const s = sessions.get(id)
  if (!s) throw fail(404, 'no such session')
  if (rest === '' && req.method === 'DELETE') {
    const result = await close(s)
    sessions.delete(id)
    return json(res, 200, result)
  }
  if (rest === '/log' && req.method === 'GET') return json(res, 200, s.log)
  if (s.closing) throw fail(410, 'session closed')
  if (rest === '/view' && req.method === 'GET') return res.writeHead(200, { 'content-type': 'text/html' }).end(viewPage)
  if (rest === '/screenshot' && req.method === 'GET') {
    const png = await s.screenshot()
    return res.writeHead(200, { 'content-type': 'image/png' }).end(png)
  }
  if (rest.startsWith('/files/')) {
    const path = decodeURIComponent(rest.slice('/files'.length))
    if (req.method === 'GET') {
      const data = await s.readFile(path).catch(e => { throw fail(404, e.message) })
      return res.writeHead(200, { 'content-type': 'application/octet-stream' }).end(data)
    }
    if (req.method === 'PUT') {
      await s.writeFile(path, await body(req))
      return res.writeHead(204).end()
    }
  }
  throw fail(404, 'no such route')
}

const server = http.createServer((req, res) => route(req, res).catch(e => json(res, e.status ?? 500, { error: e.message })))

// CDP websockets go straight through to the session's browser; /view/drive marks a person at the controls.
server.on('upgrade', (req: http.IncomingMessage, socket: net.Socket, head: Buffer) => {
  socket.on('error', () => socket.destroy())
  const [, id, rest] = new URL(req.url!, 'http://x').pathname.match(/^\/sessions\/([^/]+)(\/cdp|\/view\/watch|\/view\/drive)$/) ?? []
  const s = sessions.get(id)
  if (req.headers.authorization !== `Bearer ${key}` || !s || s.closing) return socket.end('HTTP/1.1 404 Not Found\r\nconnection: close\r\n\r\n')
  const up = net.connect(s.cdpSocket)
  up.on('error', () => socket.destroy())
  const headers: Record<string, unknown> = { ...req.headers, host: 'localhost' }
  delete headers.authorization
  delete headers.origin
  up.write(`GET ${s.wsPath} HTTP/1.1\r\n${Object.entries(headers).map(([k, v]) => `${k}: ${v}\r\n`).join('')}\r\n`)
  up.write(head)
  socket.pipe(up).pipe(socket)
  if (rest === '/view/drive') {
    s.drivers++
    socket.on('close', () => s.drivers--)
  }
})

await podman(['rm', '-f', '-t', '0', '--filter', `label=${label}`])
fs.rmSync(runDir, { recursive: true, force: true })
fs.mkdirSync(runDir, { mode: 0o700 })
server.listen(port, host, () => console.log(`rollforward-browser listening on ${host}:${port}`))
