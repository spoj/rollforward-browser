import { execFileSync, spawn } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'
import type { Server } from 'node:net'
import { chromium, type Browser, type Page } from 'playwright-core'
import { startProxy, type Entry, type Site } from './proxy.ts'

export type AuditShot = { seq: number, at: string, url: string, jpeg: Buffer }
const MAX_SHOTS = 60, SHOT_SETTLE_MS = 600, SHOT_MIN_INTERVAL_MS = 2500

const pem = execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=rollforward-browser', '-days', '3650', '-keyout', '-', '-out', '-'], { stdio: ['ignore', 'pipe', 'ignore'] }).toString()
const tlsKey = { key: pem.slice(0, pem.indexOf('-----BEGIN CERTIFICATE')), cert: pem.slice(pem.indexOf('-----BEGIN CERTIFICATE')) }
const spki = crypto.createHash('sha256').update(new crypto.X509Certificate(tlsKey.cert).publicKey.export({ type: 'spki', format: 'der' })).digest('base64')

const containerFlags = ['--network', 'none', '--userns', 'keep-id', '--read-only', '--tmpfs', '/tmp:size=2g', '--memory', '2g', '--pids-limit', '1024',
  '--cap-drop', 'all', '--security-opt', 'no-new-privileges', '--log-driver', 'none']

// A passkey needs a window of the browser's own, for Windows Hello, a security key or a phone, which a headless browser never
// shows: a page asking for one waits for good, as Microsoft's sign-in did for an account that has one. So every page, in every tab
// and before its own scripts, sees a browser without passkeys and signs in another way, and a request for one fails at once, as one
// a person cancels does.
const noPasskeys = `(() => {
  delete window.PublicKeyCredential
  const c = navigator.credentials
  if (!c) return
  for (const name of ['get', 'create']) {
    const own = c[name].bind(c)
    c[name] = options => options && options.publicKey ? Promise.reject(new DOMException('This browser has no passkeys', 'NotAllowedError')) : own(options)
  }
})()`

const cdpVersion = (sock: string) => new Promise<string>((resolve, reject) =>
  http.get({ socketPath: sock, path: '/json/version' }, res => {
    let body = ''
    res.on('data', c => body += c).on('end', () => resolve(new URL(JSON.parse(body).webSocketDebuggerUrl).pathname))
  }).on('error', reject))

export class BrowserSession {
  log: Entry[] = []
  shots: AuditShot[] = []
  shotSeq = 0
  drivers = 0
  driverGen = 0
  wsPath = ''
  proxy?: Server
  pw?: Browser
  id: string
  dir: string
  label: string
  site: Site
  audit: boolean
  cdpSocket: string
  container: string
  private lastShotAt = 0
  private lastJpeg?: Buffer
  private shotTimer?: NodeJS.Timeout
  private shotPage?: Page
  private shotGen = 0
  private frameGen = 0
  private taintedPages = new WeakSet<Page>()
  private pwCheck?: Promise<{ blocked: boolean, sig: string }>
  private capturing = false
  private pendingShot = false
  private stopped = false

  constructor(id: string, dir: string, label: string, site: Site, audit = false) {
    this.id = id
    this.dir = dir
    this.label = label
    this.site = site
    this.audit = audit
    this.cdpSocket = `${dir}/cdp.sock`
    this.container = `rollforward-browser-${id}`
  }

  async start(state: unknown, cdpUrl: string, headers: Record<string, string>) {
    fs.mkdirSync(this.dir, { mode: 0o700 })
    this.proxy = startProxy(`${this.dir}/proxy.sock`, this.site, tlsKey, () => this.drivers > 0, this.log, this.audit ? () => this.scheduleShot() : undefined, () => this.driverGen)
    await podman(['run', '-d', '--rm', '--name', this.container, '--label', this.label, ...containerFlags, '-v', `${this.dir}:/run/rollforward-browser`, 'rollforward-browser', spki])
    for (let i = 0; !this.wsPath; i++) {
      this.wsPath = await cdpVersion(this.cdpSocket).catch(e => { if (i === 100) throw e; return '' })
      if (!this.wsPath) await new Promise(r => setTimeout(r, 100))
    }
    this.pw = await chromium.connectOverCDP(cdpUrl, { headers, noDefaults: true })
    const ctx = this.pw.contexts()[0]
    await ctx.addInitScript(noPasskeys)
    if (state) await ctx.setStorageState(state as any)
    if (this.audit) {
      const watch = (p: Page) => {
        p.on('frameattached', () => { this.frameGen++ })
        p.on('framedetached', () => { this.frameGen++ })
        p.on('framenavigated', () => { this.frameGen++; this.scheduleShot(p) })
        p.on('load', () => { if (this.drivers === 0) this.taintedPages.delete(p) })
        p.on('download', () => this.scheduleShot(p))
      }
      ctx.on('page', p => {
        if (this.drivers > 0) this.taintedPages.add(p)
        watch(p)
        this.scheduleShot(p)
      })
      for (const p of ctx.pages()) watch(p)
    }
    if (this.site.start_url) await (ctx.pages()[0] ?? await ctx.newPage()).goto(this.site.start_url, { waitUntil: 'commit' })
  }

  private taintOpenPages() {
    for (const p of this.pw?.contexts()[0]?.pages() ?? []) this.taintedPages.add(p)
  }

  onDriverStart() {
    this.drivers++
    this.driverGen++
    this.taintOpenPages()
    clearTimeout(this.shotTimer)
    this.shotTimer = undefined
    this.shotPage = undefined
    this.pendingShot = false
  }

  onDriverEnd() {
    this.taintOpenPages()
    this.drivers = Math.max(0, this.drivers - 1)
    this.driverGen++
  }

  private scheduleShot(page?: Page) {
    if (!this.audit || this.stopped || this.drivers > 0) return
    if (page) this.shotPage = page
    this.shotGen = this.driverGen
    if (this.shotTimer) return
    const delay = Math.max(SHOT_SETTLE_MS, SHOT_MIN_INTERVAL_MS - (Date.now() - this.lastShotAt))
    this.shotTimer = setTimeout(() => {
      this.shotTimer = undefined
      void this.captureAudit()
    }, delay)
    this.shotTimer.unref?.()
  }

  // Fail closed: blocked if any frame (including open shadow roots) has a visible password field, any DOM/attribute mutation occurs during capture, throws, stalls past 1s, or a prior check is still stalled.
  private async hasVisiblePassword(p: Page, arm = false): Promise<{ blocked: boolean, sig: string }> {
    if (this.pwCheck) return { blocked: true, sig: '' }
    const run = Promise.all(p.frames().map(f => f.evaluate((doArm: boolean) => {
      const w = globalThis as Record<string, any>
      const hasPw = (n: any): boolean => {
        if (!n) return false
        if (n.nodeType === 1 && n.tagName === 'INPUT' && n.type === 'password') return true
        if (n.querySelector?.('input[type="password"]')) return true
        if (n.shadowRoot && hasPw(n.shadowRoot)) return true
        for (const el of n.querySelectorAll?.('*') ?? []) if (el.shadowRoot && hasPw(el.shadowRoot)) return true
        return false
      }
      if (typeof w.__rfPwEpoch !== 'number') {
        if (!doArm) return { blocked: true, epoch: -1 }
        w.__rfPwEpoch = 0
        w.__rfPwRoots = new WeakSet()
        w.__rfPwMo = new MutationObserver(ms => {
          for (const m of ms) {
            if (m.type === 'attributes') {
              const el = m.target as any
              if (el?.nodeType === 1 && ((el.tagName === 'INPUT' && (m.attributeName === 'type' || el.type === 'password')) || hasPw(el))) { w.__rfPwEpoch++; return }
            } else if ([...m.addedNodes, ...m.removedNodes].some(hasPw)) { w.__rfPwEpoch++; return }
          }
        })
      }
      const observeRoot = (root: Node) => {
        if (w.__rfPwRoots.has(root)) return
        w.__rfPwRoots.add(root)
        w.__rfPwMo.observe(root, { subtree: true, childList: true, attributes: true })
      }
      const scan = (root: ParentNode): boolean => {
        observeRoot(root)
        for (const el of root.querySelectorAll('*')) {
          if (el.tagName === 'INPUT' && (el as HTMLInputElement).type === 'password') {
            const r = el.getBoundingClientRect(), st = getComputedStyle(el)
            if (r.width > 0 && r.height > 0 && st.visibility !== 'hidden' && st.display !== 'none') return true
          }
          if (el.shadowRoot && scan(el.shadowRoot)) return true
        }
        return false
      }
      const vis = scan(document.documentElement || document)
      return { blocked: vis, epoch: w.__rfPwEpoch as number }
    }, arm).catch(() => ({ blocked: true, epoch: -1 })))).then(res => ({
      blocked: res.some(r => r.blocked),
      sig: res.map(r => r.epoch).join(','),
    }))
    this.pwCheck = run
    run.finally(() => { if (this.pwCheck === run) this.pwCheck = undefined })
    let t: NodeJS.Timeout | undefined
    return Promise.race([
      run,
      new Promise<{ blocked: boolean, sig: string }>(r => { t = setTimeout(() => r({ blocked: true, sig: '' }), 1000); t.unref?.() }),
    ]).finally(() => clearTimeout(t))
  }

  private async captureAudit() {
    if (!this.audit || this.stopped || this.drivers > 0 || this.driverGen !== this.shotGen || !this.pw?.isConnected()) return
    if (this.capturing) { this.pendingShot = true; return }
    this.capturing = true
    try {
      const gen = this.shotGen
      const pages = this.pw.contexts()[0]?.pages() ?? []
      const p = (this.shotPage && !this.shotPage.isClosed() && pages.includes(this.shotPage)) ? this.shotPage : pages.at(-1)
      this.shotPage = undefined
      if (!p || p.isClosed() || this.taintedPages.has(p)) return
      const urlBefore = p.url(), fg = this.frameGen
      const pw1 = await this.hasVisiblePassword(p, true)
      if (pw1.blocked) return
      if (this.stopped || this.drivers > 0 || this.driverGen !== gen || this.frameGen !== fg || p.isClosed()) return
      const jpeg = await p.screenshot({ type: 'jpeg', quality: 65, timeout: 3000 }).catch(() => null)
      if (!jpeg || this.stopped || this.drivers > 0 || this.driverGen !== gen || this.frameGen !== fg || p.isClosed() || p.url() !== urlBefore) return
      // Re-check password fields, mutation epoch, and frame stability after capture so a transient login modal/iframe mid-screenshot is never retained.
      const pw2 = await this.hasVisiblePassword(p, false)
      if (pw2.blocked || pw2.sig !== pw1.sig) return
      if (this.stopped || this.drivers > 0 || this.driverGen !== gen || this.frameGen !== fg) return
      this.lastShotAt = Date.now()
      if (this.lastJpeg?.equals(jpeg)) return
      this.lastJpeg = jpeg
      this.shots.push({ seq: ++this.shotSeq, at: new Date().toISOString(), url: urlBefore, jpeg })
      if (this.shots.length > MAX_SHOTS) this.shots.shift()
    } catch {
      // Best-effort audit capture must never affect the browser session.
    } finally {
      this.capturing = false
      if (this.pendingShot && !this.stopped && this.drivers === 0) {
        this.pendingShot = false
        this.scheduleShot()
      }
    }
  }

  // The browser may be gone (crashed, or closed by the agent's code): then there is no state to return.
  async close() {
    this.stopped = true
    clearTimeout(this.shotTimer)
    this.shotTimer = undefined
    try {
      return { state: this.pw?.isConnected() ? await this.pw.contexts()[0].storageState() : null, log: this.log }
    } finally {
      this.shots = []
      this.lastJpeg = undefined
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
