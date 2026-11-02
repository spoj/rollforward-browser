import http from 'node:http'
import https from 'node:https'
import tls from 'node:tls'
import net from 'node:net'
import dns from 'node:dns'
import { Duplex } from 'node:stream'

export type Site = { hosts: string[], start_url?: string, reads_that_post?: string[] }
export type Entry = { t: string, method: string, url: string, status: number, blocked?: string, error?: string, live?: true }
type Target = { scheme: string, authority: string }

const internal = new net.BlockList()
for (const [a, n] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.168.0.0', 16]] as const) internal.addSubnet(a, n, 'ipv4')
for (const [a, n] of [['::1', 128], ['::', 128], ['fc00::', 7], ['fe80::', 10], ['::ffff:0:0', 96]] as const) internal.addSubnet(a, n, 'ipv6')

const reads = new Set(['GET', 'HEAD', 'OPTIONS'])
const hopByHop = ['connection', 'keep-alive', 'proxy-connection', 'proxy-authorization', 'proxy-authenticate', 'te', 'trailer', 'transfer-encoding', 'upgrade']

// A tunnel that isn't TLS (ws:// goes through CONNECT too), wrapped so the HTTP server reads what was already peeked.
const plain = (socket: net.Socket) => {
  const d = new Duplex({
    read: () => socket.resume(),
    write: (chunk, encoding, cb) => socket.write(chunk, encoding, cb),
    final: cb => socket.end(cb),
    destroy: (err, cb) => { socket.destroy(); cb(err) },
  })
  socket.on('data', c => d.push(c) || socket.pause())
  socket.on('end', () => d.push(null))
  return d
}

// One proxy per browser session, on a unix socket only that session's container can reach.
// CONNECT tunnels are opened locally (TLS ends here, with a key the browser is told to accept),
// so every request is seen whole: checked against the site's hosts and the write rule, then logged.
export function startProxy(path: string, site: Site, key: { key: string, cert: string }, isLive: () => boolean, log: Entry[]) {
  const hosts = site.hosts.map(h => h.toLowerCase())
  const exact = new Set(hosts.filter(h => !h.startsWith('*.')))
  const suffixes = hosts.filter(h => h.startsWith('*.')).map(h => h.slice(1))
  const allowed = (host: string) => exact.has(host) || suffixes.some(s => host.endsWith(s))
  const readsThatPost = (site.reads_that_post ?? []).map(p => new RegExp('^' + p.split('*').map(RegExp.escape).join('.*') + '$'))
  const secureContext = tls.createSecureContext(key)
  const agents = { 'http:': new http.Agent({ keepAlive: true }), 'https:': new https.Agent({ keepAlive: true }) }

  const lookup = (host: string, opts: dns.LookupOptions, cb: (...a: any[]) => void) =>
    dns.lookup(host, { all: true }, (err, addrs) => {
      if (err) return cb(err)
      const ok = exact.has(host) ? addrs : addrs.filter(a => !internal.check(a.address, a.family === 6 ? 'ipv6' : 'ipv4'))
      if (!ok.length) return cb(new Error(`${host} resolves only to internal addresses`))
      opts.all ? cb(null, ok) : cb(null, ok[0].address, ok[0].family)
    })

  // Inside a tunnel, origin-form only; outside, absolute http(s) URLs only. Anything else is malformed.
  const urlOf = (req: http.IncomingMessage) => {
    const t = (req.socket as any).target as Target | undefined
    if (t ? !req.url!.startsWith('/') : !/^https?:\/\//.test(req.url!)) return null
    return URL.parse(t ? `${t.scheme}://${t.authority}${req.url}` : req.url!)
  }

  const check = (req: http.IncomingMessage, url: URL | null) =>
    !url ? 'malformed request'
      : !allowed(url.hostname) ? 'host not on the list'
      : !reads.has(req.method!) && !isLive() && !readsThatPost.some(r => r.test(url.href)) ? 'writes are off'
      : undefined

  const record = (req: http.IncomingMessage, url: URL | null, status: number, extra: Partial<Entry> = {}) =>
    log.push({ t: new Date().toISOString(), method: req.method!, url: url?.href ?? req.url!, status, ...extra, ...(isLive() ? { live: true as const } : {}) })

  const upstreamOptions = (req: http.IncomingMessage, url: URL) => {
    const headers = { ...req.headers, host: url.host }
    for (const h of hopByHop) delete headers[h]
    return { method: req.method, headers, lookup, agent: agents[url.protocol as 'http:'], servername: net.isIP(url.hostname) ? undefined : url.hostname }
  }

  const forward = (req: http.IncomingMessage, res: http.ServerResponse) => {
    const url = urlOf(req)
    const blocked = check(req, url)
    if (blocked) {
      record(req, url, 403, { blocked })
      res.writeHead(403, { 'content-type': 'text/plain' }).end(`machines: ${blocked}: ${req.method} ${url?.href ?? req.url}\n`)
      return
    }
    const up = (url!.protocol === 'https:' ? https : http).request(url, upstreamOptions(req, url), r => {
      record(req, url, r.statusCode!)
      const headers = { ...r.headers }
      for (const h of hopByHop) delete headers[h]
      res.writeHead(r.statusCode!, headers)
      r.pipe(res)
    })
    up.on('error', e => {
      record(req, url, 502, { error: e.message })
      if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' }).end(`machines: ${e.message}\n`)
      else res.destroy()
    })
    req.pipe(up)
  }

  const forwardUpgrade = (req: http.IncomingMessage, socket: net.Socket, head: Buffer) => {
    socket.on('error', () => socket.destroy())
    const url = urlOf(req)
    const blocked = check(req, url)
    if (blocked) {
      record(req, url, 403, { blocked })
      socket.end('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n')
      return
    }
    const opts = upstreamOptions(req, url)
    opts.headers.connection = 'upgrade'
    opts.headers.upgrade = req.headers.upgrade
    const up = (url.protocol === 'https:' ? https : http).request(url, opts)
    up.on('upgrade', (r, upSocket, upHead) => {
      upSocket.on('error', () => socket.destroy())
      socket.on('close', () => upSocket.destroy())
      record(req, url, 101)
      socket.write(`HTTP/1.1 101 Switching Protocols\r\n${Object.entries(r.headers).map(([k, v]) => `${k}: ${v}\r\n`).join('')}\r\n`)
      upSocket.write(head)
      socket.write(upHead)
      upSocket.pipe(socket).pipe(upSocket)
    })
    up.on('response', r => {
      record(req, url, r.statusCode!)
      socket.end(`HTTP/1.1 ${r.statusCode} ${r.statusMessage}\r\nconnection: close\r\n\r\n`)
    })
    up.on('error', e => {
      record(req, url, 502, { error: e.message })
      socket.end('HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n')
    })
    up.end()
  }

  const inner = http.createServer(forward)
  inner.on('upgrade', forwardUpgrade)
  const outer = http.createServer(forward)
  outer.on('upgrade', forwardUpgrade)
  outer.on('connect', (req: http.IncomingMessage, socket: net.Socket, head: Buffer) => {
    socket.on('error', () => socket.destroy())
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
    const start = (first: Buffer) => {
      socket.pause()
      socket.unshift(first)
      const s = first[0] === 0x16 ? new tls.TLSSocket(socket, { isServer: true, secureContext, ALPNProtocols: ['http/1.1'] }) : plain(socket)
      ;(s as any).target = { scheme: first[0] === 0x16 ? 'https' : 'http', authority: req.url! } satisfies Target
      inner.emit('connection', s)
    }
    head.length ? start(head) : socket.once('data', start)
  })
  outer.on('close', () => Object.values(agents).forEach(a => a.destroy()))
  outer.listen(path)
  return outer
}
