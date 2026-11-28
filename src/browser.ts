import { execFileSync, spawn } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'
import { chromium, type Browser, type Page } from 'playwright-core'
import { CdpSessionTap, type CdpEntry } from './cdp-tap.ts'
import {
  InFlightBudgetTracker,
  startProxy,
  toLegacyLog,
  type AuditV2Config,
  type LogRecord,
  type PolicyHookConfig,
  type ProxyServer,
  type Site,
  type V2Entry,
} from './proxy.ts'
import { SecretVault, isAuthUrl, sanitizeUrl, scrubText } from './redact.ts'

export type ShotTrigger = 'nav' | 'load' | 'write' | 'download' | 'tab' | 'file-upload'

export type AuditShot = {
  seq: number
  at: string
  url: string
  trigger: ShotTrigger
  httpCursor: number
  cdpCursor: number
  jpeg: Buffer
}

export type HudEvent = {
  n: number
  t: string
  kind: 'http' | 'cdp' | 'live_start' | 'live_end'
  method?: string
  status?: number
  blocked?: string
  isWrite?: boolean
  severity?: 'high'
  detail: string
}

export type SealSnapshot = {
  sealed: true
  state: unknown
  logCursor: number
  cdpCursor: number
  shotCursor: number
  gaps: {
    droppedGets: number
    droppedCdp: number
    droppedShots: number
    refusedFull: number
  }
}

const MAX_SHOTS = 60
const MAX_SHOT_BYTES = 20 * 1024 * 1024
const MAX_SINGLE_SHOT_JPEG_BYTES = 5 * 1024 * 1024
const SHOT_SETTLE_MS = 500
const SHOT_MIN_INTERVAL_MS = 1_500
const SHOT_BG_WRITE_INTERVAL_MS = 10_000
const MAX_SHOTS_PAGE_BYTES = 8 * 1024 * 1024
const LIVE_COOLDOWN_MS = 5_000
const MAX_HUD_EVENTS = 100
const SEAL_STEP_TIMEOUT_MS = 10_000

const withTimeout = <T>(p: Promise<T>, ms: number, fallback: T): Promise<T> => {
  let timer: NodeJS.Timeout | undefined
  return Promise.race([
    p.catch(() => fallback),
    new Promise<T>(r => { timer = setTimeout(() => r(fallback), ms); timer.unref() }),
  ]).finally(() => clearTimeout(timer))
}

const pem = execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=rollforward-browser', '-days', '3650', '-keyout', '-', '-out', '-'], { stdio: ['ignore', 'pipe', 'ignore'] }).toString()
const tlsKey = { key: pem.slice(0, pem.indexOf('-----BEGIN CERTIFICATE')), cert: pem.slice(pem.indexOf('-----BEGIN CERTIFICATE')) }
const spki = crypto.createHash('sha256').update(new crypto.X509Certificate(tlsKey.cert).publicKey.export({ type: 'spki', format: 'der' })).digest('base64')

const containerFlags = ['--network', 'none', '--userns', 'keep-id', '--read-only', '--tmpfs', '/tmp:size=2g', '--memory', '2g', '--pids-limit', '1024',
  '--cap-drop', 'all', '--security-opt', 'no-new-privileges', '--log-driver', 'none']

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

export type BrowserSessionOptions = {
  auditV2?: AuditV2Config
  inFlightTracker?: InFlightBudgetTracker
  clientId?: string
  policyHook?: PolicyHookConfig
  sealTimeoutMs?: number
}

export class BrowserSession {
  log: LogRecord[] = []
  shots: AuditShot[] = []
  shotSeq = 0
  shotsDropped = 0
  drivers = 0
  driverGen = 0
  lastDriverEndedAt = 0
  siteConfigRev = 0
  wsPath = ''
  proxy?: ProxyServer
  pw?: Browser
  id: string
  dir: string
  label: string
  site: Site
  audit: boolean
  auditV2?: AuditV2Config
  cdpSocket: string
  container: string
  internalNonce: string
  vault: SecretVault
  cdpTap?: CdpSessionTap
  sealedAt?: number

  private opts: BrowserSessionOptions
  private lastShotAt = 0
  private lastJpeg?: Buffer
  private shotTimer?: NodeJS.Timeout
  private shotPage?: Page
  private shotTrigger: ShotTrigger = 'nav'
  private shotPriority = 0
  private shotGen = 0
  private frameGen = 0
  private taintedPages = new WeakSet<Page>()
  private capturing = false
  private pendingShot = false
  private pendingShotTrigger: ShotTrigger = 'nav'
  private pendingShotPriority = 0
  private stopped = false
  private sealPromise?: Promise<SealSnapshot>
  private sealedSnapshot?: SealSnapshot
  private shotBytes = 0

  // B1 Activity HUD ring buffer (100 entries)
  private hudEvents: HudEvent[] = []
  private hudCursor = 0
  private hudWriteCount = 0
  private hudBlockedCount = 0

  constructor(id: string, dir: string, label: string, site: Site, audit = false, opts: BrowserSessionOptions = {}) {
    this.id = id
    this.dir = dir
    this.label = label
    this.site = site
    this.audit = audit
    this.auditV2 = opts.auditV2
    this.opts = opts
    this.cdpSocket = `${dir}/cdp.sock`
    this.container = `rollforward-browser-${id}`
    this.internalNonce = crypto.randomBytes(16).toString('hex')
    this.vault = new SecretVault()

    if (site.headers) {
      for (const val of Object.values(site.headers)) {
        this.vault.addTrustedHeader(val)
      }
    }

    if (this.auditV2 && this.auditV2.cdp !== false) {
      // Dedicated per-session CDP parser budget (isolated from HTTP proxy & /view/drive tap so unfinished frames cannot starve proxy!)
      this.cdpTap = new CdpSessionTap({
        projection: this.auditV2.projection ?? 'semantic',
        vault: this.vault,
        isLive: () => this.isLiveOrCooldown(),
        onEvent: e => this.recordHudCdp(e),
        onFileUpload: () => this.scheduleShot(undefined, 'file-upload', false),
      })
    }
  }

  isSealed(): boolean {
    return this.sealedSnapshot !== undefined
  }

  isLiveOrCooldown(): boolean {
    return this.drivers > 0 || (this.lastDriverEndedAt > 0 && Date.now() - this.lastDriverEndedAt < LIVE_COOLDOWN_MS)
  }

  verifyInternalNonce(headerVal: string | string[] | undefined): boolean {
    if (typeof headerVal !== 'string') return false
    const a = Buffer.from(headerVal, 'utf8')
    const b = Buffer.from(this.internalNonce, 'utf8')
    return a.length === b.length && crypto.timingSafeEqual(a, b)
  }

  private pushHudEvent(ev: Omit<HudEvent, 'n'>) {
    if (!this.auditV2 || this.auditV2.hud === false) return
    const item: HudEvent = { n: ++this.hudCursor, ...ev }
    this.hudEvents.push(item)
    if (this.hudEvents.length > MAX_HUD_EVENTS) {
      this.hudEvents.shift()
    }
  }

  private recordHudHttp(rec: LogRecord) {
    if (!this.auditV2 || this.auditV2.hud === false) return
    const r = rec as any
    if (r.rec === '_summary' || r.rec === 'http_end') return
    // Suppress live, liveAtEnd, and 5s cooldown at insertion (§4)
    if (this.isLiveOrCooldown() || r.live || r.liveAtEnd) return
    const e = rec as V2Entry
    if (e.isWrite) this.hudWriteCount++
    if (e.blocked) this.hudBlockedCount++
    const rawDetail = e.authority ? `${e.authority}${e.path}` : e.path || '/'
    const detail = scrubText(rawDetail.slice(0, 160), this.vault).text
    this.pushHudEvent({
      t: e.t,
      kind: 'http',
      method: e.effectiveMethod ?? e.method,
      status: e.status,
      ...(e.blocked && { blocked: e.blocked }),
      ...(e.isWrite && { isWrite: true }),
      detail,
    })
  }

  private recordHudCdp(entry: CdpEntry) {
    if (!this.auditV2 || this.auditV2.hud === false) return
    if (this.isLiveOrCooldown() || entry.live) return
    let hostPath = ''
    if (typeof entry.summary?.url === 'string') {
      const parsed = URL.parse(entry.summary.url)
      if (parsed) {
        const san = sanitizeUrl(parsed, { projection: 'semantic', vault: this.vault })
        hostPath = ` ${san.authority}${san.path}`
      }
    }
    const detail = scrubText(`${entry.method}${hostPath}`.slice(0, 160), this.vault).text
    this.pushHudEvent({
      t: entry.t,
      kind: 'cdp',
      method: entry.method,
      ...(entry.severity && { severity: entry.severity }),
      detail,
    })
  }

  getActivity(after: number) {
    const oldestCursor = this.hudEvents.length ? this.hudEvents[0].n : this.hudCursor
    const events = this.hudEvents.filter(e => e.n > after)
    // Report dropped count strictly relative to caller's `after` cursor!
    const dropped = this.hudEvents.length > 0
      ? Math.max(0, (this.hudEvents[0].n - 1) - after)
      : Math.max(0, this.hudCursor - after)
    const nextCursor = events.length ? events[events.length - 1].n : Math.max(after, oldestCursor)
    return {
      live: this.drivers > 0,
      oldestCursor,
      nextCursor,
      dropped,
      writeCount: this.hudWriteCount,
      blockedCount: this.hudBlockedCount,
      events,
    }
  }

  async start(state: unknown, cdpUrl: string, headers: Record<string, string>) {
    if (state) this.vault.ingestStorageState(state)
    fs.mkdirSync(this.dir, { mode: 0o700 })
    const proxyOpts = this.auditV2 || this.opts.policyHook
      ? {
          sessionId: this.id,
          clientId: this.opts.clientId ?? 'default',
          auditV2: this.auditV2,
          vault: this.vault,
          policyHook: this.opts.policyHook,
          getSiteConfigRev: () => this.siteConfigRev,
          getCdpCursor: () => this.cdpTap?.currentCursor ?? 0,
          isLiveOrCooldown: () => this.isLiveOrCooldown(),
          onEntry: (entry: LogRecord) => this.recordHudHttp(entry),
          onWriteDetail: this.audit ? ({ dest }: { dest?: string }) => this.scheduleShot(undefined, 'write', dest === 'empty') : undefined,
          inFlightTracker: this.opts.inFlightTracker,
        }
      : undefined
    this.proxy = startProxy(
      `${this.dir}/proxy.sock`,
      this.site,
      tlsKey,
      () => this.drivers > 0,
      this.log,
      this.audit ? () => this.scheduleShot(undefined, 'write', false) : undefined,
      () => this.driverGen,
      proxyOpts,
    )
    await podman(['run', '-d', '--rm', '--name', this.container, '--label', this.label, ...containerFlags, '-v', `${this.dir}:/run/rollforward-browser`, 'rollforward-browser', spki])
    for (let i = 0; !this.wsPath; i++) {
      this.wsPath = await cdpVersion(this.cdpSocket).catch(e => { if (i === 100) throw e; return '' })
      if (!this.wsPath) await new Promise(r => setTimeout(r, 100))
    }
    this.pw = await chromium.connectOverCDP(cdpUrl, {
      headers: { ...headers, 'x-rf-internal': this.internalNonce },
      noDefaults: true,
    })
    const ctx = this.pw.contexts()[0]
    await ctx.addInitScript(noPasskeys)
    if (state) await ctx.setStorageState(state as any)
    if (this.audit) {
      const watch = (p: Page) => {
        p.on('frameattached', () => { this.frameGen++ })
        p.on('framedetached', () => { this.frameGen++ })
        p.on('framenavigated', f => {
          this.frameGen++
          if (f === p.mainFrame()) this.scheduleShot(p, 'nav', false)
        })
        p.on('load', () => {
          if (this.drivers === 0) this.taintedPages.delete(p)
          this.scheduleShot(p, 'load', false)
        })
        p.on('download', () => this.scheduleShot(p, 'download', false))
      }
      ctx.on('page', p => {
        if (this.drivers > 0) this.taintedPages.add(p)
        watch(p)
        this.scheduleShot(p, 'tab', false)
      })
      for (const p of ctx.pages()) watch(p)
    }
    if (this.site.start_url) await (ctx.pages()[0] ?? await ctx.newPage()).goto(this.site.start_url, { waitUntil: 'commit' })
  }

  private taintOpenPages() {
    for (const p of this.pw?.contexts()[0]?.pages() ?? []) this.taintedPages.add(p)
  }

  onDriverStart() {
    const wasIdle = this.drivers === 0
    this.drivers++
    this.driverGen++
    this.taintOpenPages()
    clearTimeout(this.shotTimer)
    this.shotTimer = undefined
    this.shotPage = undefined
    this.shotPriority = 0
    this.pendingShot = false
    this.pendingShotPriority = 0
    if (wasIdle) {
      this.pushHudEvent({ t: new Date().toISOString(), kind: 'live_start', detail: 'Human took control' })
    }
  }

  onDriverEnd() {
    this.taintOpenPages()
    this.drivers = Math.max(0, this.drivers - 1)
    this.driverGen++
    this.lastDriverEndedAt = Date.now()
    if (this.drivers === 0) {
      this.pushHudEvent({ t: new Date().toISOString(), kind: 'live_end', detail: 'Control returned' })
    }
  }

  private scheduleShot(page?: Page, trigger: ShotTrigger = 'nav', bgWrite = false) {
    if (!this.audit || this.stopped || this.drivers > 0) return
    const priority = bgWrite ? 1 : 2
    if (this.capturing) {
      this.pendingShot = true
      if (priority >= this.pendingShotPriority) {
        this.pendingShotPriority = priority
        this.pendingShotTrigger = trigger
        if (page) this.shotPage = page
      }
      return
    }
    // Never let a lower-priority background write overwrite a pending high-priority trigger or delay it!
    if (this.shotTimer) {
      if (priority < this.shotPriority) return
      if (priority > this.shotPriority) {
        // Reschedule earlier for high-priority event (e.g., download/file-upload overriding 10s bg-write timer)
        clearTimeout(this.shotTimer)
        this.shotTimer = undefined
      } else {
        if (page) this.shotPage = page
        this.shotTrigger = trigger
        this.shotGen = this.driverGen
        return
      }
    }

    if (page) this.shotPage = page
    this.shotTrigger = trigger
    this.shotPriority = priority
    this.shotGen = this.driverGen
    const minInterval = bgWrite ? SHOT_BG_WRITE_INTERVAL_MS : SHOT_MIN_INTERVAL_MS
    const delay = Math.max(SHOT_SETTLE_MS, minInterval - (Date.now() - this.lastShotAt))
    this.shotTimer = setTimeout(() => {
      this.shotTimer = undefined
      this.shotPriority = 0
      void this.captureAudit()
    }, delay)
    this.shotTimer.unref?.()
  }

  private async isSafeForShot(p: Page): Promise<boolean> {
    if (isAuthUrl(p.url())) return false
    const check = Promise.all(
      p.frames().map(async f => {
        if (isAuthUrl(f.url())) return true
        return (await f.locator('input[type=password]:visible').count()) > 0
      }),
    ).then(hits => !hits.some(Boolean))
    return withTimeout(check, 1_000, false)
  }

  private async captureAudit() {
    if (!this.audit || this.stopped || this.drivers > 0 || this.driverGen !== this.shotGen || !this.pw?.isConnected()) return
    if (this.capturing) { this.pendingShot = true; return }
    this.capturing = true
    try {
      const gen = this.shotGen
      const trigger = this.shotTrigger
      const pages = this.pw.contexts()[0]?.pages() ?? []
      const p = (this.shotPage && !this.shotPage.isClosed() && pages.includes(this.shotPage)) ? this.shotPage : pages.at(-1)
      this.shotPage = undefined
      if (!p || p.isClosed() || this.taintedPages.has(p)) return
      const urlBefore = p.url(), fg = this.frameGen
      if (!(await this.isSafeForShot(p))) return
      if (this.stopped || this.drivers > 0 || this.driverGen !== gen || this.frameGen !== fg || p.isClosed()) return
      const jpeg = await p.screenshot({ type: 'jpeg', quality: 65, timeout: 3000 }).catch(() => null)
      if (!jpeg || jpeg.length > MAX_SINGLE_SHOT_JPEG_BYTES || this.stopped || this.drivers > 0 || this.driverGen !== gen || this.frameGen !== fg || p.isClosed() || p.url() !== urlBefore) return
      this.lastShotAt = Date.now()
      if (this.lastJpeg?.equals(jpeg)) return
      this.lastJpeg = jpeg
      const sanUrl = this.auditV2 ? sanitizeUrl(urlBefore, { projection: this.auditV2.projection ?? 'semantic', vault: this.vault }).url : urlBefore
      this.shots.push({
        seq: ++this.shotSeq,
        at: new Date().toISOString(),
        url: sanUrl,
        trigger,
        httpCursor: this.proxy?.controller.getCurrentCursor() ?? 0,
        cdpCursor: this.cdpTap?.currentCursor ?? 0,
        jpeg,
      })
      this.shotBytes += jpeg.length
      while (this.shots.length > MAX_SHOTS || (this.shotBytes > MAX_SHOT_BYTES && this.shots.length > 1)) {
        const evicted = this.shots.shift()!
        this.shotBytes -= evicted.jpeg.length
        this.shotsDropped++
      }
    } catch {
      // Best-effort audit capture must never affect the browser session.
    } finally {
      this.capturing = false
      if (this.pendingShot && !this.stopped && this.drivers === 0) {
        const nextTrigger = this.pendingShotTrigger
        const nextBg = this.pendingShotPriority === 1
        this.pendingShot = false
        this.pendingShotPriority = 0
        this.scheduleShot(undefined, nextTrigger, nextBg)
      }
    }
  }

  getShotsV2(after: number) {
    const oldestSeq = this.shots.length ? this.shots[0].seq : this.shotSeq
    const dropped = this.shots.length > 0
      ? Math.max(0, (this.shots[0].seq - 1) - after)
      : Math.max(0, this.shotSeq - after)
    const items: Array<{ seq: number; at: string; url: string; trigger: ShotTrigger; httpCursor: number; cdpCursor: number; jpeg: string }> = []
    let pageBytes = 128 // envelope overhead
    let lastIdx = -1

    for (let i = 0; i < this.shots.length; i++) {
      const s = this.shots[i]
      if (s.seq <= after) continue
      const item = {
        seq: s.seq,
        at: s.at,
        url: s.url,
        trigger: s.trigger,
        httpCursor: s.httpCursor,
        cdpCursor: s.cdpCursor,
        jpeg: s.jpeg.toString('base64'),
      }
      const entryBytes = Buffer.byteLength(JSON.stringify(item), 'utf8') + 1
      if (items.length > 0 && pageBytes + entryBytes > MAX_SHOTS_PAGE_BYTES) break
      items.push(item)
      pageBytes += entryBytes
      lastIdx = i
    }

    const hasMore = lastIdx >= 0 && lastIdx < this.shots.length - 1
    const nextSeq = items.length > 0 ? items[items.length - 1].seq : Math.max(after, oldestSeq)
    return {
      oldestSeq,
      nextSeq,
      hasMore,
      dropped,
      items,
    }
  }

  seal(): Promise<SealSnapshot> {
    return (this.sealPromise ??= this.doSeal())
  }

  private async doSeal(): Promise<SealSnapshot> {
    this.stopped = true
    this.sealedAt = Date.now()
    clearTimeout(this.shotTimer)
    this.shotTimer = undefined

    // Finalize in-flight proxy requests & stop admission SYNCHRONOUSLY before awaiting storageState/shutdown
    // so in-flight writes record dispatch:'unknown' and accurate incompleteAtSeal counts!
    const pSnap = this.proxy?.controller.finalizeAtSeal() ?? { logCursor: 0, droppedGets: 0, refusedFull: 0 }

    const timeoutMs = this.opts.sealTimeoutMs ?? SEAL_STEP_TIMEOUT_MS
    let state: unknown = null
    try {
      state = this.pw?.isConnected() ? await withTimeout(this.pw.contexts()[0].storageState(), timeoutMs, null) : null
    } finally {
      if (this.pw) await withTimeout(this.pw.close(), timeoutMs, undefined)
      await podman(['rm', '-f', '-i', '-t', '0', this.container]).catch(() => {})
      fs.rmSync(this.dir, { recursive: true, force: true })
    }

    const cSnap = this.cdpTap?.seal() ?? { cdpCursor: 0, droppedCdp: 0 }

    this.sealedSnapshot = {
      sealed: true,
      state,
      logCursor: pSnap.logCursor,
      cdpCursor: cSnap.cdpCursor,
      shotCursor: this.shotSeq,
      gaps: {
        droppedGets: pSnap.droppedGets,
        droppedCdp: cSnap.droppedCdp,
        droppedShots: this.shotsDropped,
        refusedFull: pSnap.refusedFull,
      },
    }
    return this.sealedSnapshot
  }

  reclaim() {
    this.proxy?.controller.clear()
    this.cdpTap?.clear()
    this.log.length = 0
    this.shots = []
    this.shotBytes = 0
    this.lastJpeg = undefined
    this.hudEvents = []
    this.vault.clear()
    if (this.sealedSnapshot) this.sealedSnapshot.state = null
  }

  async close() {
    const snap = await this.seal()
    const result = { state: snap.state, log: toLegacyLog(this.log) }
    this.reclaim()
    return result
  }

  async screenshot() {
    return await this.pw!.contexts()[0].pages().at(-1)!.screenshot()
  }

  async page() {
    const p = this.pw!.contexts()[0].pages().at(-1)!
    await p.waitForLoadState('load')
    return { url: p.url(), password: await p.isVisible('input[type=password]') }
  }

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
