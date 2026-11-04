// A fake vendor portal for tests: a sign-in form, a session cookie that expires and changes on every visit
// to the home page, reads that are POSTs (like the ERP's web client), a write, a download, and a link to another host.
// `tokens` has each request's host and the x-bot-token it carried, if any.
import https from 'node:https'
import crypto from 'node:crypto'
import type { AddressInfo } from 'node:net'

export function startPortal(tls: { key: string, cert: string }) {
  const sessions = new Map<string, { user: string, expires: number }>()
  const writes: string[] = []
  const tokens: string[] = []
  const server = https.createServer(tls, async (req, res) => {
    const host = req.headers.host!.split(':')[0]
    const url = new URL(req.url!, `https://${req.headers.host}`)
    const body = Buffer.concat(await req.toArray()).toString()
    const sid = /(?:^|; )sid=(\w+)/.exec(req.headers.cookie ?? '')?.[1]
    tokens.push(`${host} ${req.headers['x-bot-token'] ?? '-'}`)
    const session = sid && sessions.get(sid)
    const page = (html: string) => res.writeHead(200, { 'content-type': 'text/html' }).end(`<!doctype html><title>Portal</title>${html}`)
    const signedIn = (user: string) => {
      const id = crypto.randomBytes(12).toString('hex')
      sessions.set(id, { user, expires: Date.now() + 600_000 })
      return `sid=${id}; Max-Age=600; Path=/; Secure; HttpOnly; SameSite=Lax`
    }

    if (host === 'other.localhost') return page('<h1>Another host</h1>')
    if (url.pathname === '/login' && req.method === 'GET')
      return page('<form method=post action=/login><input id=user name=user><input id=password name=password type=password><button>Sign in</button></form>')
    if (url.pathname === '/login' && req.method === 'POST') {
      const user = new URLSearchParams(body).get('user')!
      return res.writeHead(303, { location: '/', 'set-cookie': signedIn(user) }).end()
    }
    if (!session || session.expires < Date.now()) return res.writeHead(302, { location: '/login' }).end()
    if (url.pathname === '/' && req.method === 'GET') {
      sessions.delete(sid)
      res.setHeader('set-cookie', signedIn(session.user))
      return page(`<h1>Welcome ${session.user}</h1>
        <script>localStorage.setItem('portal-pref', 'dense')</script>
        <a id=download href=/download>Download</a>
        <a id=other href="https://other.localhost:${url.port}/">Other host</a>
        <form id=update method=post action=/update><input name=amount value=1><button>Update</button></form>`)
    }
    if (url.pathname === '/report' && req.method === 'POST')
      return res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ user: session.user, rows: [['cash', 100]] }))
    if (url.pathname === '/update' && req.method === 'POST') {
      writes.push(body)
      return page('<h1>Updated</h1>')
    }
    if (url.pathname === '/download' && req.method === 'GET')
      return res.writeHead(200, { 'content-type': 'text/csv', 'content-disposition': 'attachment; filename=report.csv' }).end('account,amount\ncash,100\n')
    res.writeHead(404).end()
  })
  server.on('upgrade', (req, socket) => {
    const accept = crypto.createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: upgrade\r\nsec-websocket-accept: ${accept}\r\n\r\n`)
    socket.write(Buffer.from([0x81, 5, ...Buffer.from('hello')]))
  })
  server.listen(0, '::')
  return { server, sessions, writes, tokens, port: () => (server.address() as AddressInfo).port }
}
