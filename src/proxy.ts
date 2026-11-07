import http from 'node:http'
import https from 'node:https'
import tls from 'node:tls'
import net from 'node:net'
import dns from 'node:dns'
import { Duplex } from 'node:stream'

// `public`, for a person's own site rather than one an admin set up: none of its hosts, exact ones included, reaches an internal
// address, and it goes over https only.
export type Site = { hosts: string[], start_url?: string, headers?: Record<string, string>, public?: boolean }
export type Entry = { t: string, method: string, url: string, status: number, dest?: string, from?: string, blocked?: string, error?: string, live?: true }
type Target = { scheme: string, authority: string }

// Internal addresses, which only a site's exact hosts may be at, as an intranet's are; but none is ever this machine's own, a loopback
// address, or a link-local one, such as the cloud's metadata service, or Azure's WireServer.
const internal = new net.BlockList(), never = new net.BlockList()
for (const [a, n] of [['0.0.0.0', 8], ['127.0.0.0', 8], ['169.254.0.0', 16], ['168.63.129.16', 32]] as const) for (const l of [internal, never]) l.addSubnet(a, n, 'ipv4')
for (const [a, n] of [['::', 127], ['fe80::', 10]] as const) for (const l of [internal, never]) l.addSubnet(a, n, 'ipv6')
for (const [a, n] of [['10.0.0.0', 8], ['100.64.0.0', 10], ['172.16.0.0', 12], ['192.168.0.0', 16]] as const) internal.addSubnet(a, n, 'ipv4')
internal.addSubnet('fc00::', 7, 'ipv6')
// An IPv4-mapped IPv6 answer, ::ffff:a.b.c.d, is checked as its IPv4 address. A ::ffff:0:0/96 rule can't say that: Node's BlockList
// matches every IPv4 address against it, which made every wildcard host's IPv4 addresses internal.
export const isInternal = (address: string, family: number, list = internal) => {
  const v4 = family === 6 ? /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address)?.[1] : undefined
  return v4 ? list.check(v4, 'ipv4') : list.check(address, family === 6 ? 'ipv6' : 'ipv4')
}
export const isNever = (address: string, family: number) => isInternal(address, family, never)

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
// so every request is seen whole: checked against the site's hosts, then logged.
export function startProxy(path: string, site: Site, key: { key: string, cert: string }, isLive: () => boolean, log: Entry[]) {
  // The site's hosts as they are now: a PUT adds those its person allows as the session goes (server.ts).
  const exact = (host: string) => site.hosts.some(h => h.toLowerCase() === host)
  const allowed = (host: string) => exact(host) || site.hosts.some(h => h.startsWith('*.') && host.endsWith(h.slice(1).toLowerCase()))
  // The site's headers, such as a token its sign-in needs that its pages never send, go only to start_url's origin, added here, so
  // the browser, and anyone on its CDP, never holds them.
  const origin = site.start_url && new URL(site.start_url).origin
  const secureContext = tls.createSecureContext(key)
  // One address per connection, IPv4 where the host has one, with no racing of the two: on a machine with no IPv6 route, Node's
  // happy eyeballs falls back to IPv6 whenever IPv4 is slower than 500ms, as in a page's burst of requests, and fails.
  const agents = { 'http:': new http.Agent({ keepAlive: true, autoSelectFamily: false }), 'https:': new https.Agent({ keepAlive: true, autoSelectFamily: false }) }

  const lookup = (host: string, _opts: dns.LookupOptions, cb: (...a: any[]) => void) =>
    dns.lookup(host, { all: true }, (err, addrs) => {
      if (err) return cb(err)
      const strict = site.public || !exact(host), ok = addrs.filter(a => !(strict ? isInternal : isNever)(a.address, a.family))
      if (!ok.length) return cb(new Error(`${host} resolves only to ${strict ? 'internal' : 'loopback, link-local or WireServer'} addresses`))
      const one = ok.find(a => a.family === 4) ?? ok[0]
      cb(null, one.address, one.family)
    })

  // Inside a tunnel, origin-form only; outside, absolute http(s) URLs only. Anything else is malformed.
  const urlOf = (req: http.IncomingMessage) => {
    const t = (req.socket as any).target as Target | undefined
    if (t ? !req.url!.startsWith('/') : !/^https?:\/\//.test(req.url!)) return null
    return URL.parse(t ? `${t.scheme}://${t.authority}${req.url}` : req.url!)
  }

  const check = (req: http.IncomingMessage, url: URL | null) =>
    !url ? 'malformed request'
      : site.public && url.protocol !== 'https:' ? 'https only'
      : !allowed(url.hostname) ? 'host not on the list'
      : undefined

  // What the browser says of each request, as it sends it: its kind (Sec-Fetch-Dest) and the page it came from (Referer).
  const record = (req: http.IncomingMessage, url: URL | null, status: number, extra: Partial<Entry> = {}) => {
    const dest = req.headers['sec-fetch-dest'] as string | undefined, from = req.headers.referer
    log.push({ t: new Date().toISOString(), method: req.method!, url: url?.href ?? req.url!, status, ...(dest && { dest }), ...(from && { from }), ...extra, ...(isLive() ? { live: true as const } : {}) })
  }

  const upstreamOptions = (req: http.IncomingMessage, url: URL) => {
    const headers = { ...req.headers, ...(url.origin === origin && site.headers), host: url.host }
    for (const h of hopByHop) delete headers[h]
    return { method: req.method, headers, lookup, agent: agents[url.protocol as 'http:'], servername: net.isIP(url.hostname) ? undefined : url.hostname }
  }

  const forward = (req: http.IncomingMessage, res: http.ServerResponse) => {
    const url = urlOf(req)
    const blocked = check(req, url)
    if (blocked) {
      record(req, url, 403, { blocked })
      res.writeHead(403, { 'content-type': 'text/plain' }).end(`rollforward-browser: ${blocked}: ${req.method} ${url?.href ?? req.url}\n`)
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
      if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' }).end(`rollforward-browser: ${e.message}\n`)
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
