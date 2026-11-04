import { execFileSync, spawn } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'
import type { Server } from 'node:net'
import { chromium, type Browser } from 'playwright-core'
import { startProxy, type Entry, type Site } from './proxy.ts'

const pem = execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=rollforward-browser', '-days', '3650', '-keyout', '-', '-out', '-'], { stdio: ['ignore', 'pipe', 'ignore'] }).toString()
const tlsKey = { key: pem.slice(0, pem.indexOf('-----BEGIN CERTIFICATE')), cert: pem.slice(pem.indexOf('-----BEGIN CERTIFICATE')) }
const spki = crypto.createHash('sha256').update(new crypto.X509Certificate(tlsKey.cert).publicKey.export({ type: 'spki', format: 'der' })).digest('base64')

const containerFlags = ['--network', 'none', '--userns', 'keep-id', '--read-only', '--tmpfs', '/tmp:size=2g', '--memory', '2g', '--pids-limit', '1024',
  '--cap-drop', 'all', '--security-opt', 'no-new-privileges', '--log-driver', 'none']

const cdpVersion = (sock: string) => new Promise<string>((resolve, reject) =>
  http.get({ socketPath: sock, path: '/json/version' }, res => {
    let body = ''
    res.on('data', c => body += c).on('end', () => resolve(new URL(JSON.parse(body).webSocketDebuggerUrl).pathname))
  }).on('error', reject))

export class BrowserSession {
  log: Entry[] = []
  drivers = 0
  wsPath = ''
  proxy?: Server
  pw?: Browser
  id: string
  dir: string
  label: string
  site: Site
  cdpSocket: string
  container: string

  constructor(id: string, dir: string, label: string, site: Site) {
    this.id = id
    this.dir = dir
    this.label = label
    this.site = site
    this.cdpSocket = `${dir}/cdp.sock`
    this.container = `rollforward-browser-${id}`
  }

  async start(state: unknown, cdpUrl: string, headers: Record<string, string>) {
    fs.mkdirSync(this.dir, { mode: 0o700 })
    this.proxy = startProxy(`${this.dir}/proxy.sock`, this.site, tlsKey, () => this.drivers > 0, this.log)
    await podman(['run', '-d', '--rm', '--name', this.container, '--label', this.label, ...containerFlags, '-v', `${this.dir}:/run/rollforward-browser`, 'rollforward-browser', spki])
    for (let i = 0; !this.wsPath; i++) {
      this.wsPath = await cdpVersion(this.cdpSocket).catch(e => { if (i === 100) throw e; return '' })
      if (!this.wsPath) await new Promise(r => setTimeout(r, 100))
    }
    this.pw = await chromium.connectOverCDP(cdpUrl, { headers, noDefaults: true })
    const ctx = this.pw.contexts()[0]
    if (state) await ctx.setStorageState(state as any)
    if (this.site.start_url) await (ctx.pages()[0] ?? await ctx.newPage()).goto(this.site.start_url, { waitUntil: 'commit' })
  }

  // The browser may be gone (crashed, or closed by the agent's code): then there is no state to return.
  async close() {
    try {
      return { state: this.pw?.isConnected() ? await this.pw.contexts()[0].storageState() : null, log: this.log }
    } finally {
      await this.pw?.close()
      await podman(['rm', '-f', '-i', '-t', '0', this.container])
      this.proxy?.close()
      fs.rmSync(this.dir, { recursive: true, force: true })
    }
  }

  async screenshot() {
    return await this.pw!.contexts()[0].pages().at(-1)!.screenshot()
  }

  // The newest tab once loaded: its address, and whether it shows a password field, as a sign-in page does.
  async page() {
    const p = this.pw!.contexts()[0].pages().at(-1)!
    await p.waitForLoadState('load')
    return { url: p.url(), password: await p.isVisible('input[type=password]') }
  }

  // The newest tab loaded again, as a host its page needed is allowed.
  async reload() {
    await this.pw!.contexts()[0].pages().at(-1)!.reload({ waitUntil: 'commit' })
  }

  readFile(path: string) {
    return podman(['exec', this.container, 'cat', '--', path])
  }

  async writeFile(path: string, data: Buffer) {
    await podman(['exec', '-i', this.container, 'sh', '-c', 'mkdir -p "$(dirname "$1")" && cat > "$1"', 'sh', path], data)
  }
}

export function podman(args: string[], input?: Buffer) {
  const p = spawn('podman', args, { stdio: [input ? 'pipe' : 'ignore', 'pipe', 'pipe'] })
  p.stdin?.end(input)
  const out: Buffer[] = [], err: Buffer[] = []
  p.stdout.on('data', c => out.push(c))
  p.stderr.on('data', c => err.push(c))
  return new Promise<Buffer>((resolve, reject) => p.on('close', code =>
    code ? reject(new Error(Buffer.concat(err).toString().trim())) : resolve(Buffer.concat(out))))
}
