import http from 'node:http'
import net from 'node:net'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import { BrowserSession, podman } from './browser.ts'
import { WindowsSession, startPool, windowsDir } from './windows.ts'

const port = Number(process.env.MACHINES_PORT ?? 8797)
const key = process.env.MACHINES_KEY
if (!key) throw new Error('MACHINES_KEY is not set')
const runDir = `${os.tmpdir()}/machines-${port}`
const label = `machines=${port}`
const viewPage = fs.readFileSync(new URL('view.html', import.meta.url))

type Result = { state?: unknown, log?: unknown[] }
type Session = (BrowserSession | WindowsSession) & { expires?: number, timer?: NodeJS.Timeout, closing?: Promise<Result> }
const sessions = new Map<string, Session>()

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
  const s: Session = spec.kind === 'browser' ? new BrowserSession(id, `${runDir}/${id}`, label, spec.site)
    : spec.kind === 'windows' ? new WindowsSession(id)
    : (() => { throw fail(400, `unknown kind: ${spec.kind}`) })()
  sessions.set(id, s)
  try {
    if (s instanceof BrowserSession) await s.start(spec.state, `ws://127.0.0.1:${port}/sessions/${id}/cdp`, { authorization: `Bearer ${key}` })
    else await s.start()
  } catch (e) {
    sessions.delete(id)
    await close(s)
    throw e
  }
  const ttl = (spec.ttl_s ?? 3600) * 1000
  s.expires = Date.now() + ttl
  s.timer = setTimeout(() => close(s).catch(e => console.error(`closing ${id}:`, e)), ttl)
  return s instanceof BrowserSession ? { id, cdp: `/sessions/${id}/cdp`, view: `/sessions/${id}/view` } : { id }
}

async function route(req: http.IncomingMessage, res: http.ServerResponse) {
  if (req.headers.authorization !== `Bearer ${key}`) throw fail(401, 'bad key')
  const { pathname } = new URL(req.url!, 'http://x')
  if (pathname === '/sessions' && req.method === 'POST') return json(res, 201, await open(JSON.parse((await body(req)).toString())))
  if (pathname === '/sessions' && req.method === 'GET') return json(res, 200, [...sessions.values()].map(s => ({ id: s.id, kind: s.kind, expires: s.expires, closed: !!s.closing })))
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
  if (rest === '/run' && req.method === 'POST' && s instanceof WindowsSession) {
    const { lang, script, timeout_s } = JSON.parse((await body(req)).toString())
    return json(res, 200, await s.run(lang, script, timeout_s))
  }
  if (rest === '/view' && req.method === 'GET' && s instanceof BrowserSession) return res.writeHead(200, { 'content-type': 'text/html' }).end(viewPage)
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
  if (req.headers.authorization !== `Bearer ${key}` || !(s instanceof BrowserSession) || s.closing) return socket.end('HTTP/1.1 404 Not Found\r\nconnection: close\r\n\r\n')
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
startPool(`${windowsDir}/vms-${port}`)
server.listen(port, '127.0.0.1', () => console.log(`machines listening on 127.0.0.1:${port}`))
