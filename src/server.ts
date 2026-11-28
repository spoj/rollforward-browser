import http from 'node:http'
import net from 'node:net'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import { domainToASCII } from 'node:url'
import { BrowserSession, podman, type SealSnapshot } from './browser.ts'
import { blocklist, isBlocked, loadBlocklists } from './blocklists.ts'
import { createDriveVaultTap } from './cdp-tap.ts'
import { InFlightBudgetTracker, toLegacyLog, type AuditV2Config } from './proxy.ts'

const VERSION = '0.3.0'
const port = Number(process.env.BROWSER_PORT ?? 8797)
const host = process.env.BROWSER_HOST ?? '127.0.0.1'
const auditV2Enabled = process.env.BROWSER_AUDIT_V2 !== '0'
const postTtlGcMs = Number(process.env.BROWSER_POST_TTL_GC_MS ?? 25 * 60_000)
const maxSealedPerClient = Number(process.env.BROWSER_MAX_SEALED_PER_CLIENT ?? 8)

const keys = process.env.BROWSER_KEYS ?? (process.env.BROWSER_KEY ? `default:${process.env.BROWSER_KEY}` : '')
if (!keys.trim()) throw new Error('BROWSER_KEYS or BROWSER_KEY must be set')
const clients = keys.trim().split(/\s+/).map(pair => {
  const match = /^([a-z0-9-]+):(\S+)$/.exec(pair)
  if (!match) throw new Error('BROWSER_KEYS: whitespace-separated name:key pairs, names a-z 0-9 -')
  const [, name, key] = match
  return { name, key, hash: crypto.hash('sha256', `Bearer ${key}`, 'buffer') }
})
if (new Set(clients.map(c => c.name)).size !== clients.length || new Set(clients.map(c => c.key)).size !== clients.length) throw new Error('BROWSER_KEYS: names and keys must be unique')
const runDir = `${os.tmpdir()}/rollforward-browser-${port}`
const label = `rollforward-browser=${port}`
const viewPage = fs.readFileSync(new URL('view.html', import.meta.url))
const inFlightTracker = new InFlightBudgetTracker()
// Dedicated /view/drive parser budget (256 KiB/session, 1 MiB/client, 8 MiB/process), isolated from HTTP proxy & external CDP!
const driveParserTracker = new InFlightBudgetTracker(8 * 1024 * 1024, 1 * 1024 * 1024, 256 * 1024)

type Session = BrowserSession & {
  client: string
  expires?: number
  timer?: NodeJS.Timeout
  gcTimer?: NodeJS.Timeout
  closing?: Promise<SealSnapshot>
}
const sessions = new Map<string, Session>()

// An update (scripts/update.ts) drains the service before it moves the checkout: no session opens, and once every session has been
// collected with DELETE, its request log with it, or 30 minutes have passed, GET /drained answers 200, for the update to move it and
// restart the service.
let drainUntil = 0
process.on('SIGUSR2', () => { drainUntil ||= Date.now() + 30 * 60_000 })

const fail = (status: number, message: string) => Object.assign(new Error(message), { status })
const json = (res: http.ServerResponse, status: number, body: unknown, extraHeaders?: Record<string, string>) =>
  res.writeHead(status, { 'content-type': 'application/json', ...extraHeaders }).end(JSON.stringify(body))
const body = async (req: http.IncomingMessage) => Buffer.concat(await req.toArray())
const names = (list: unknown) => Array.isArray(list) && list.every(h => typeof h === 'string' && /^(\*\.)?[a-z0-9_.-]+$|^\[[0-9a-f:.]+\]$/i.test(h))
const exactNames = (list: unknown) => Array.isArray(list) && list.every(h => typeof h === 'string' && /^[a-z0-9_.-]+$|^\[[0-9a-f:.]+\]$/i.test(h))

const sealSession = (s: Session, scheduleGc = false): Promise<SealSnapshot> => {
  clearTimeout(s.timer)
  if (!s.closing) {
    s.closing = s.seal()
  }
  if (scheduleGc && !s.gcTimer) {
    void s.closing.then(() => {
      if (!sessions.has(s.id) || s.gcTimer) return
      s.gcTimer = setTimeout(() => {
        if (!sessions.has(s.id) || !s.isSealed()) return
        s.reclaim()
        sessions.delete(s.id)
      }, postTtlGcMs)
      s.gcTimer.unref()
    }).catch(() => {})
  }
  return s.closing
}

function validateAuditV2(raw: unknown): AuditV2Config | undefined {
  if (raw === undefined || raw === null) return undefined
  if (typeof raw !== 'object' || Array.isArray(raw)) throw fail(400, 'auditV2 must be an object')
  const cfg = raw as Record<string, unknown>
  if (cfg.v !== 2) throw fail(400, 'auditV2.v must be 2')
  if (cfg.projection !== undefined && cfg.projection !== 'semantic' && cfg.projection !== 'semantic+samples') {
    throw fail(400, 'auditV2.projection must be "semantic" or "semantic+samples"')
  }
  if (cfg.cdp !== undefined && typeof cfg.cdp !== 'boolean') throw fail(400, 'auditV2.cdp must be boolean')
  if (cfg.hud !== undefined && typeof cfg.hud !== 'boolean') throw fail(400, 'auditV2.hud must be boolean')
  if (!auditV2Enabled) return undefined
  return {
    v: 2,
    projection: (cfg.projection as AuditV2Config['projection']) ?? 'semantic',
    cdp: (cfg.cdp as boolean | undefined) ?? true,
    hud: (cfg.hud as boolean | undefined) ?? true,
    ...(cfg.intent && typeof cfg.intent === 'object' ? { intent: cfg.intent as AuditV2Config['intent'] } : {}),
  }
}

function checkSealedCap(clientName: string) {
  let count = 0
  for (const s of sessions.values()) {
    if (s.client === clientName && s.closing) count++
  }
  if (count >= maxSealedPerClient) {
    throw fail(503, 'too many sealed undrained sessions')
  }
}

// A site's lists and headers are checked here, as one that the proxy can't use would end the service, every client's sessions with it.
async function open(spec: any, client: typeof clients[number]) {
  const { site } = spec
  if (!site || !names(site.hosts) || !names(site.except ?? []) || site.via && !names(site.via.hosts)) throw fail(400, 'hosts, except and via.hosts: names such as sso.example.com, or *.example.com for any under it')
  const rawInternal = spec.internalHosts ?? site.internalHosts
  if (rawInternal !== undefined && !exactNames(rawInternal)) throw fail(400, 'internalHosts: exact hostnames without wildcards')
  const siteCfg = rawInternal !== undefined ? { ...site, internalHosts: rawInternal } : site
  const auditV2 = validateAuditV2(spec.auditV2)
  try {
    for (const [name, value] of Object.entries({ ...siteCfg.headers, ...siteCfg.via && { 'proxy-authorization': `Bearer ${siteCfg.via.token}` } })) {
      http.validateHeaderName(name)
      http.validateHeaderValue(name, value)
    }
  } catch (e: any) {
    throw fail(400, e.message)
  }
  if (siteCfg.open && !blocklist) throw fail(503, 'blocklists not loaded yet')
  checkSealedCap(client.name)

  const id = crypto.randomBytes(8).toString('hex')
  const s: Session = Object.assign(
    new BrowserSession(id, `${runDir}/${id}`, label, siteCfg, spec.audit === true, {
      auditV2,
      inFlightTracker,
      clientId: client.name,
    }),
    { client: client.name },
  )
  sessions.set(id, s)
  try {
    await s.start(spec.state, `ws://${host}:${port}/sessions/${id}/cdp`, { authorization: `Bearer ${client.key}` })
  } catch (e) {
    sessions.delete(id)
    await sealSession(s)
    s.reclaim()
    throw e
  }
  const ttl = (spec.ttl_s ?? 3600) * 1000
  s.expires = Date.now() + ttl
  s.timer = setTimeout(() => {
    sealSession(s, true).catch(e => console.error(`sealing ${id}:`, e))
  }, ttl)
  return {
    id,
    cdp: `/sessions/${id}/cdp`,
    view: `/sessions/${id}/view`,
    ...(s.audit && { shots: `/sessions/${id}/shots` }),
    ...(s.auditV2 && {
      seal: `/sessions/${id}/seal`,
      logV2: `/sessions/${id}/log`,
      cdpLog: `/sessions/${id}/cdp-log`,
      activity: `/sessions/${id}/view/activity`,
    }),
  }
}

async function route(req: http.IncomingMessage, res: http.ServerResponse) {
  const hash = crypto.hash('sha256', req.headers.authorization ?? '', 'buffer')
  const client = clients.find(c => crypto.timingSafeEqual(c.hash, hash))
  if (!client) throw fail(401, 'bad key')
  const url = URL.parse(req.url!, 'http://x')
  if (!url) throw fail(400, 'invalid url')
  const { pathname, searchParams } = url
  if (pathname === '/capabilities' && req.method === 'GET') {
    return json(res, 200, { version: VERSION, auditV2: auditV2Enabled ? 2 : 0, seal: true, activity: true })
  }
  if (pathname === '/blocked' && req.method === 'GET') {
    if (!blocklist) throw fail(503, 'blocklists not loaded yet')
    return json(res, 200, Object.fromEntries(searchParams.getAll('host').map(host => [host, isBlocked(domainToASCII(host))])))
  }
  if (pathname === '/drained' && req.method === 'GET') return json(res, drainUntil && (!sessions.size || Date.now() > drainUntil) ? 200 : 503, { open: sessions.size })
  if (pathname === '/sessions' && req.method === 'POST' && drainUntil) throw fail(503, 'updating: try again in a few minutes')
  if (pathname === '/sessions' && req.method === 'POST') return json(res, 201, await open(JSON.parse((await body(req)).toString()), client))
  if (pathname === '/sessions' && req.method === 'GET') return json(res, 200, [...sessions.values()].filter(s => s.client === client.name).map(s => ({ id: s.id, expires: s.expires, closed: !!s.closing })))
  const [, id, rest] = pathname.match(/^\/sessions\/([^/]+)(.*)$/) ?? []
  const s = sessions.get(id)
  if (!s || s.client !== client.name) throw fail(404, 'no such session')

  // ---- Routes ABOVE `if (s.closing)` so sealed & TTL-expired sessions remain drainable (§2.1.1) ----
  if (rest === '' && req.method === 'DELETE') {
    clearTimeout(s.gcTimer)
    if (searchParams.get('sealed') === '1') {
      await sealSession(s)
      s.reclaim()
      sessions.delete(id)
      return json(res, 200, { deleted: true })
    }
    const snap = await sealSession(s)
    const result = { state: snap.state, log: toLegacyLog(s.log) }
    s.reclaim()
    sessions.delete(id)
    return json(res, 200, result)
  }

  if (rest === '/seal' && req.method === 'POST') {
    const snap = await sealSession(s, true)
    return json(res, 200, snap)
  }

  if (rest === '/log' && req.method === 'GET') {
    if (s.auditV2 && (searchParams.has('after') || searchParams.get('v') === '2')) {
      const after = Math.max(0, Number(searchParams.get('after') ?? '0') || 0)
      const limit = Math.min(500, Math.max(1, Number(searchParams.get('limit') ?? '500') || 500))
      return json(res, 200, s.proxy!.controller.getLogPage(after, limit))
    }
    return json(res, 200, toLegacyLog(s.log))
  }

  if (rest === '/cdp-log' && req.method === 'GET') {
    if (!s.auditV2) throw fail(404, 'cdp log not enabled')
    if (!s.cdpTap) {
      return json(res, 200, { oldestCursor: 0, nextCursor: 0, hasMore: false, dropped: 0, entries: [] })
    }
    const after = Math.max(0, Number(searchParams.get('after') ?? '0') || 0)
    const limit = Math.min(500, Math.max(1, Number(searchParams.get('limit') ?? '500') || 500))
    return json(res, 200, s.cdpTap.getPage(after, limit))
  }

  if (rest === '/shots' && req.method === 'GET') {
    const after = Math.max(0, Number(searchParams.get('after') ?? '0') || 0)
    if (s.auditV2 || searchParams.get('v') === '2') {
      return json(res, 200, s.getShotsV2(after))
    }
    const items = s.shots.filter(x => x.seq > after).slice(0, 20)
    return json(res, 200, items.map(x => ({ seq: x.seq, at: x.at, url: x.url, jpeg: x.jpeg.toString('base64') })))
  }

  // ---- Active-session-only routes ----
  if (s.closing) throw fail(410, 'session closed')

  if (rest === '/view' && req.method === 'GET') return res.writeHead(200, { 'content-type': 'text/html' }).end(viewPage)
  if (rest === '/view/activity' && req.method === 'GET') {
    if (!s.auditV2 || s.auditV2.hud === false) throw fail(404, 'activity hud not enabled')
    const after = Math.max(0, Number(searchParams.get('after') ?? '0') || 0)
    return json(res, 200, s.getActivity(after), { 'cache-control': 'no-store' })
  }
  if (rest === '/page' && req.method === 'GET') return json(res, 200, await s.page())
  if (rest === '/hosts' && req.method === 'PUT') {
    const { hosts } = JSON.parse((await body(req)).toString())
    if (!names(hosts)) throw fail(400, 'hosts: names such as sso.example.com, or *.example.com for any under it')
    s.site.hosts = hosts
    return json(res, 200, { hosts })
  }
  if (rest === '/reload' && req.method === 'POST') return (await s.reload(), json(res, 200, {}))
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

const server = http.createServer((req, res) => route(req, res).catch(e =>
  res.headersSent || res.destroyed ? res.destroy() : json(res, e.status ?? 500, { error: e.message })))

// What a watcher may ask of the browser: its tabs, and a screencast of one.
const WATCH = new Set(['Target.setDiscoverTargets', 'Target.attachToTarget', 'Target.detachFromTarget', 'Page.startScreencast', 'Page.stopScreencast', 'Page.screencastFrameAck'])

// A watcher's websocket frames, each read whole, never compressed: ping, pong and close go on as they came; a text frame, whole and
// small, of a method it may ask goes on as its JSON parsed and written again, so the browser reads the method the filter did; anything
// else, such as input, a script, or a frame unmasked, binary or in parts, ends the socket, so watching never drives.
function watchOnly(socket: net.Socket, up: net.Socket, head: Buffer) {
  let buf = Buffer.alloc(0)
  const end = () => (socket.destroy(), up.destroy())
  const take = (chunk: Buffer) => {
    buf = Buffer.concat([buf, chunk])
    for (;;) {
      if (buf.length < 2) return
      const n = buf[1] & 0x7f, at = n === 126 ? 4 : n === 127 ? 10 : 2
      if (buf.length < at + 4) return
      const len = n === 126 ? buf.readUInt16BE(2) : n === 127 ? Number(buf.readBigUInt64BE(2)) : n
      if (!(buf[1] & 0x80) || len > 16_384) return end()
      if (buf.length < at + 4 + len) return
      const frame = buf.subarray(0, at + 4 + len), mask = frame.subarray(at, at + 4), data = Buffer.from(frame.subarray(at + 4).map((b, i) => b ^ mask[i % 4]))
      buf = buf.subarray(frame.length)
      if ((frame[0] & 0x0f) >= 8) {
        up.write(frame)
        continue
      }
      let m
      try { m = JSON.parse(data.toString()) } catch {}
      if (frame[0] !== 0x81 || !WATCH.has(m?.method)) return end()
      const text = Buffer.from(JSON.stringify(m)), key = crypto.randomBytes(4)
      up.write(Buffer.concat([Buffer.from(text.length < 126 ? [0x81, 0x80 | text.length] : [0x81, 0xfe, text.length >> 8, text.length & 255]), key, text.map((b, i) => b ^ key[i % 4])]))
    }
  }
  take(head)
  socket.on('data', take)
}

// CDP websockets go straight through to the session's browser; /view/drive marks a person at the controls, and /view/watch passes
// only what watching asks.
server.on('upgrade', (req: http.IncomingMessage, socket: net.Socket, head: Buffer) => {
  socket.on('error', () => socket.destroy())
  const hash = crypto.hash('sha256', req.headers.authorization ?? '', 'buffer')
  const client = clients.find(c => crypto.timingSafeEqual(c.hash, hash))
  const url = client ? URL.parse(req.url!, 'http://x') : null
  const [, id, rest] = url?.pathname.match(/^\/sessions\/([^/]+)(\/cdp|\/view\/watch|\/view\/drive)$/) ?? []
  const s = id ? sessions.get(id) : undefined
  if (!client || !s || s.client !== client.name || s.closing) return socket.end('HTTP/1.1 404 Not Found\r\nconnection: close\r\n\r\n')

  const isInternalPw = rest === '/cdp' && s.verifyInternalNonce(req.headers['x-rf-internal'])
  const tapExternalCdp = rest === '/cdp' && !isInternalPw && Boolean(s.cdpTap)
  const tapDriveVault = rest === '/view/drive'

  const up = net.connect(s.cdpSocket)
  up.on('error', () => socket.destroy())
  socket.on('close', () => up.destroy())

  const headers: Record<string, unknown> = { ...req.headers, host: 'localhost' }
  delete headers.authorization
  delete headers.origin
  // Strip ALL x-rf-* headers before forwarding to Chromium (§3.1.1)
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase().startsWith('x-rf-')) delete headers[k]
  }
  // Strip sec-websocket-extensions on /view/watch, /view/drive, and tapped external /cdp (§3.1.2)
  if (rest === '/view/watch' || tapDriveVault || tapExternalCdp) {
    delete headers['sec-websocket-extensions']
  }

  up.write(`GET ${s.wsPath} HTTP/1.1\r\n${Object.entries(headers).map(([k, v]) => `${k}: ${v}\r\n`).join('')}\r\n`)

  if (rest === '/view/watch') {
    watchOnly(socket, up, head)
  } else {
    // Shared per-session/client/process /view/drive parser budget (isolated from HTTP proxy & external CDP!)
    const driveCharger = tapDriveVault
      ? {
          tryAcquire: (b: number) => driveParserTracker.tryAcquire(client.name, s.id, b),
          release: (b: number) => driveParserTracker.release(client.name, s.id, b),
        }
      : undefined
    const onTapError = () => {
      socket.destroy()
      up.destroy()
    }
    const tap = tapExternalCdp
      ? s.cdpTap!.attachConnection({ onError: onTapError })
      : tapDriveVault
        ? (s.cdpTap
            ? s.cdpTap.attachConnection({ live: true, driveVault: true, onError: onTapError })
            : createDriveVaultTap(s.vault, driveCharger, onTapError))
        : undefined
    if (tap && head.length) {
      tap.feed(head)
      if (socket.destroyed) return
    }
    up.write(head)
    if (tap) {
      socket.on('data', (c: Buffer) => tap.feed(c))
      socket.on('close', () => tap.close())
    }
    socket.pipe(up)
  }

  up.pipe(socket)
  if (rest === '/view/drive') {
    s.onDriverStart()
    socket.on('close', () => s.onDriverEnd())
  }
})

void loadBlocklists()
setInterval(loadBlocklists, 24 * 60 * 60_000)
await podman(['rm', '-f', '-t', '0', '--filter', `label=${label}`])
fs.rmSync(runDir, { recursive: true, force: true })
fs.mkdirSync(runDir, { mode: 0o700 })
server.listen(port, host, () => console.log(`rollforward-browser listening on ${host}:${port}`))
