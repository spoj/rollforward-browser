import http from 'node:http'
import https from 'node:https'
import tls from 'node:tls'
import net from 'node:net'
import dns from 'node:dns'
import { Duplex } from 'node:stream'
import { isBlocked } from './blocklists.ts'
import {
  EXTRACTOR_V,
  MAX_PREFIX_BYTES,
  decompressPrefix,
  extractSemantic,
  normalizeContentType,
  type BodyOmittedReason,
  type Completeness,
  type GraphqlOp,
  type SemanticAction,
} from './extract.ts'
import {
  REDACT_V,
  SecretVault,
  isAuthUrl,
  sanitizeUrl,
  scrubDeep,
  scrubText,
  truncateUtf8HeadTail,
  type ProjectionMode,
} from './redact.ts'

export const DESC_V = 1

export type AuditV2Config = {
  v: 2
  projection?: ProjectionMode
  cdp?: boolean
  hud?: boolean
  shots?: boolean
  intent?: { run: number; series?: string; taskSummary?: string }
}

export type SafeRequestProjection = {
  descV: 1
  redactV: 1
  extractorV: 1
  surface: 'browser' | 'api'
  target: { site: string } | { connection: string }
  seq: number
  t: string
  kind: 'http' | 'upgrade'
  scheme: 'http' | 'https'
  authority: string
  path: string
  url: string
  method: string
  effectiveMethod: string
  methodSource: 'wire' | 'x-http-method' | 'x-http-method-override' | 'x-method-override'
  isWrite: boolean
  hdr?: Record<string, string>
  dest?: string
  from?: string
  reqType?: string
  declaredBytes?: number
  prefixBytes: number
  bodyComplete: boolean
  decodeComplete: boolean
  completeness: Completeness
  actions: SemanticAction[]
  bodyShape?: Record<string, string>
  graphqlOp?: GraphqlOp
  dupKeys?: true
  cdpCursor?: number
  httpCursor?: number
  live?: true
  reqBody?: string
  reqTrunc?: true
  reqOmitted?: BodyOmittedReason
}

export type V2Entry = SafeRequestProjection & {
  n: number
  rec?: 'http'
  status: number
  blocked?: string
  error?: string
  resType?: string
  reqBytes?: number
  resBytes?: number
  headerMs?: number
  ms?: number
  dispatch: 'not_dispatched' | 'dispatched' | 'unknown'
  liveAtEnd?: true
  incomplete?: true
  logCapped?: true
}

export type LateOutcomeEntry = {
  n: number
  rec: 'http_end'
  ref: number
  t: string
  reqBytes?: number
  resBytes?: number
  ms: number
  error?: string
  incomplete?: true
}

export type SummaryEntry = {
  n: number
  rec: '_summary'
  t: string
  collapsedGets: Record<string, { count: number; bytes: number }>
  droppedGets: number
  refusedFullCount: number
  incompleteAtSeal: number
  droppedLateOutcomes?: number
}

export type LogRecord = V2Entry | LateOutcomeEntry | SummaryEntry
export type Entry = V2Entry

export class InFlightBudgetTracker {
  private processBytes = 0
  private clientBytes = new Map<string, number>()
  private sessionBytes = new Map<string, number>()
  readonly maxProcessBytes: number
  readonly maxClientBytes: number
  readonly maxSessionBytes: number

  constructor(
    maxProcessBytes = 32 * 1024 * 1024,
    maxClientBytes = 4 * 1024 * 1024,
    maxSessionBytes = 1 * 1024 * 1024,
  ) {
    this.maxProcessBytes = maxProcessBytes
    this.maxClientBytes = maxClientBytes
    this.maxSessionBytes = maxSessionBytes
  }

  tryAcquire(clientId: string, sessionId: string, bytes: number): boolean {
    if (bytes <= 0) return true
    const cCur = this.clientBytes.get(clientId) ?? 0
    const sCur = this.sessionBytes.get(sessionId) ?? 0
    if (
      this.processBytes + bytes > this.maxProcessBytes ||
      cCur + bytes > this.maxClientBytes ||
      sCur + bytes > this.maxSessionBytes
    ) {
      return false
    }
    this.processBytes += bytes
    this.clientBytes.set(clientId, cCur + bytes)
    this.sessionBytes.set(sessionId, sCur + bytes)
    return true
  }

  release(clientId: string, sessionId: string, bytes: number): void {
    if (bytes <= 0) return
    this.processBytes = Math.max(0, this.processBytes - bytes)
    const cNext = Math.max(0, (this.clientBytes.get(clientId) ?? 0) - bytes)
    if (cNext === 0) this.clientBytes.delete(clientId)
    else this.clientBytes.set(clientId, cNext)
    const sNext = Math.max(0, (this.sessionBytes.get(sessionId) ?? 0) - bytes)
    if (sNext === 0) this.sessionBytes.delete(sessionId)
    else this.sessionBytes.set(sessionId, sNext)
  }

  getProcessBytes(): number {
    return this.processBytes
  }
}

export type ProxyV2Options = {
  siteName?: string
  sessionId?: string
  clientId?: string
  auditV2?: AuditV2Config
  vault?: SecretVault
  getCdpCursor?: () => number
  isLiveOrCooldown?: () => boolean
  onEntry?: (entry: LogRecord) => void
  onWriteDetail?: (info: { dest?: string; isWrite: boolean }) => void
  inFlightTracker?: InFlightBudgetTracker
  prefixTimeoutMs?: number
  streamTimeoutMs?: number
  maxLogSoftBytes?: number
  maxLogHardBytes?: number
  maxSampleBytes?: number
  collapseGetsAfterBytes?: number
  collapseGetsAfterEntries?: number
}

export type ProxyController = {
  stopAdmission: () => void
  finalizeAtSeal: () => { logCursor: number; droppedGets: number; refusedFull: number }
  getLogPage: (after: number, limit?: number) => {
    oldestCursor: number
    nextCursor: number
    hasMore: boolean
    dropped: number
    entries: LogRecord[]
  }
  getCurrentCursor: () => number
  clear: () => void
}

export type ProxyServer = http.Server & { controller: ProxyController }

export type Site = { hosts: string[], internalHosts?: string[], start_url?: string, headers?: Record<string, string>, public?: boolean, open?: boolean, except?: string[], via?: { url: string, token: string, hosts: string[] } }
type Target = { scheme: string, authority: string }

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const OVERRIDE_HEADERS = ['x-http-method', 'x-http-method-override', 'x-method-override'] as const
const VALID_VERB_RE = /^[A-Z]{3,16}$/
const STATIC_DESTS = new Set(['image', 'font', 'style', 'script', 'audio', 'video'])
const ALLOWED_FETCH_DESTS = new Set([
  'audio', 'audioworklet', 'document', 'embed', 'empty', 'fencedframe', 'font', 'frame',
  'iframe', 'image', 'manifest', 'object', 'paintworklet', 'report', 'script',
  'serviceworker', 'sharedworker', 'style', 'track', 'video', 'webidentity', 'worker', 'xslt',
])

const MAX_ENTRY_BYTES = 12 * 1024
const MINIMAL_RESERVE_BYTES = 1024
const TAIL_RESERVE_BYTES = 64 * 1024
const MAX_PAGE_BYTES = 4 * 1024 * 1024
const MAX_COLLAPSE_BUCKETS = 64

const internal = new net.BlockList(), never = new net.BlockList()
for (const [a, n] of [['0.0.0.0', 8], ['127.0.0.0', 8], ['169.254.0.0', 16], ['168.63.129.16', 32]] as const) for (const l of [internal, never]) l.addSubnet(a, n, 'ipv4')
for (const [a, n] of [['::', 127], ['fe80::', 10]] as const) for (const l of [internal, never]) l.addSubnet(a, n, 'ipv6')
for (const [a, n] of [['10.0.0.0', 8], ['100.64.0.0', 10], ['172.16.0.0', 12], ['192.168.0.0', 16]] as const) internal.addSubnet(a, n, 'ipv4')
internal.addSubnet('fc00::', 7, 'ipv6')

export const isInternal = (address: string, family: number, list = internal) => {
  const v4 = family === 6 ? /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address)?.[1] : undefined
  return v4 ? list.check(v4, 'ipv4') : list.check(address, family === 6 ? 'ipv6' : 'ipv4')
}
export const isNever = (address: string, family: number) => isInternal(address, family, never)

const hopByHop = ['connection', 'keep-alive', 'proxy-connection', 'proxy-authorization', 'proxy-authenticate', 'te', 'trailer', 'transfer-encoding', 'upgrade']

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

function classifyMethod(method: string | undefined, headers: Record<string, string | string[] | undefined>) {
  const wireMethod = (method ?? 'GET').toUpperCase()
  const hdr: Record<string, string> = {}
  let ovHdr: typeof OVERRIDE_HEADERS[number] | undefined
  let ovVal: string | undefined
  for (const name of OVERRIDE_HEADERS) {
    const raw = headers[name]
    if (raw === undefined) continue
    const joined = Array.isArray(raw) ? raw.join(',') : raw
    hdr[name] = truncateUtf8HeadTail(joined, 256)
    if (ovVal === undefined && typeof raw === 'string') {
      ovHdr = name
      ovVal = raw.trim().toUpperCase()
    }
  }
  if (headers['soapaction'] !== undefined) {
    const raw = headers['soapaction']
    hdr.soapaction = truncateUtf8HeadTail(Array.isArray(raw) ? raw.join(',') : raw, 256)
  }
  const hasOverride = OVERRIDE_HEADERS.some(h => headers[h] !== undefined)
  const validOv = Boolean(ovVal && VALID_VERB_RE.test(ovVal))
  const effectiveMethod = validOv && (SAFE_METHODS.has(wireMethod) || !SAFE_METHODS.has(ovVal!)) ? ovVal! : wireMethod
  const methodSource: SafeRequestProjection['methodSource'] = validOv && effectiveMethod === ovVal && ovHdr ? ovHdr : 'wire'
  return { wireMethod, effectiveMethod, methodSource, hasOverride, hdr: Object.keys(hdr).length ? hdr : undefined }
}

function sanitizeDest(headers: Record<string, string | string[] | undefined>): string | undefined {
  const raw = headers['sec-fetch-dest']
  if (typeof raw !== 'string' || !raw) return undefined
  const v = raw.trim().toLowerCase()
  return ALLOWED_FETCH_DESTS.has(v) ? v : 'other'
}

function parseDeclaredBytes(headers: Record<string, string | string[] | undefined>): number | undefined {
  const cl = headers['content-length']
  if (typeof cl !== 'string') return undefined
  const n = Number(cl.trim())
  return Number.isInteger(n) && n >= 0 ? n : undefined
}

function capEntryTo12KiB(entry: V2Entry): { entry: V2Entry; bytes: number } {
  let bytes = Buffer.byteLength(JSON.stringify(entry), 'utf8')
  if (bytes <= MAX_ENTRY_BYTES) return { entry, bytes }

  const copy: V2Entry = { ...entry }
  if (copy.reqBody !== undefined) {
    const excess = bytes - MAX_ENTRY_BYTES + 128
    const curBodyBytes = Buffer.byteLength(copy.reqBody, 'utf8')
    const targetBytes = Math.max(0, curBodyBytes - excess)
    if (targetBytes <= 64) {
      delete copy.reqBody
      copy.reqTrunc = true
    } else {
      copy.reqBody = truncateUtf8HeadTail(copy.reqBody, targetBytes)
      copy.reqTrunc = true
    }
    bytes = Buffer.byteLength(JSON.stringify(copy), 'utf8')
    if (bytes <= MAX_ENTRY_BYTES) return { entry: copy, bytes }
  }

  if (copy.bodyShape) {
    const keys = Object.keys(copy.bodyShape)
    if (keys.length > 16) {
      const trimmed: Record<string, string> = {}
      for (const k of keys.slice(0, 16)) trimmed[k] = copy.bodyShape[k]
      copy.bodyShape = trimmed
    } else {
      delete copy.bodyShape
    }
    copy.reqTrunc = true
    bytes = Buffer.byteLength(JSON.stringify(copy), 'utf8')
    if (bytes <= MAX_ENTRY_BYTES) return { entry: copy, bytes }
  }

  if (copy.actions.length) {
    copy.actions = copy.actions.slice(0, 4).map(a => ({
      family: a.family,
      op: a.op,
      ...(a.resource && { resource: truncateUtf8HeadTail(a.resource, 256) }),
      coverage: a.coverage,
    }))
    bytes = Buffer.byteLength(JSON.stringify(copy), 'utf8')
    if (bytes <= MAX_ENTRY_BYTES) return { entry: copy, bytes }
  }

  const minimal = toMinimalCappedEntry(copy)
  return { entry: minimal, bytes: Buffer.byteLength(JSON.stringify(minimal), 'utf8') }
}

// Guaranteed <= MINIMAL_RESERVE_BYTES minimal record preserving full hostname in origin+pathname for checkRefused whenever it fits!
function toMinimalCappedEntry(e: V2Entry): V2Entry {
  let pathMax = 80
  let msgMax = 48
  let authMax = 255
  for (let attempt = 0; attempt < 6; attempt++) {
    const p = truncateUtf8HeadTail(e.path || '/', pathMax)
    const authority = truncateUtf8HeadTail(e.authority || '', authMax)
    const originPath = authority ? `${e.scheme}://${authority}${p}` : truncateUtf8HeadTail(e.url, pathMax)
    const minimal: V2Entry = {
      n: e.n,
      descV: DESC_V,
      redactV: REDACT_V,
      extractorV: EXTRACTOR_V,
      surface: e.surface,
      target: 'site' in e.target ? { site: truncateUtf8HeadTail(e.target.site, 32) } : e.target,
      seq: e.seq,
      t: e.t,
      kind: e.kind,
      scheme: e.scheme,
      authority,
      path: p,
      url: originPath,
      method: e.method.slice(0, 16),
      effectiveMethod: e.effectiveMethod.slice(0, 16),
      methodSource: e.methodSource,
      isWrite: e.isWrite,
      prefixBytes: e.prefixBytes,
      bodyComplete: e.bodyComplete,
      decodeComplete: e.decodeComplete,
      completeness: { transport: e.completeness.transport, decode: e.completeness.decode, extract: 'none' },
      actions: [],
      status: e.status,
      ...(e.blocked !== undefined && { blocked: truncateUtf8HeadTail(e.blocked, msgMax) }),
      ...(e.error !== undefined && { error: truncateUtf8HeadTail(e.error, msgMax) }),
      dispatch: e.dispatch,
      ...(e.live && { live: true as const }),
      ...(e.liveAtEnd && { liveAtEnd: true as const }),
      ...(e.incomplete && { incomplete: true as const }),
      logCapped: true,
    }
    if (Buffer.byteLength(JSON.stringify(minimal), 'utf8') <= MINIMAL_RESERVE_BYTES) return minimal
    pathMax = Math.max(1, Math.floor(pathMax / 2))
    msgMax = Math.max(8, Math.floor(msgMax / 2))
    if (attempt >= 3) authMax = Math.max(48, Math.floor(authMax * 0.6))
  }
  const authority = truncateUtf8HeadTail(e.authority || '', 255)
  const originPath = authority ? `${e.scheme}://${authority}/` : '/'
  return {
    n: e.n,
    descV: DESC_V,
    redactV: REDACT_V,
    extractorV: EXTRACTOR_V,
    surface: 'browser',
    target: { site: 's' },
    seq: e.seq,
    t: e.t,
    kind: e.kind,
    scheme: e.scheme,
    authority,
    path: '/',
    url: originPath,
    method: e.method.slice(0, 16),
    effectiveMethod: e.effectiveMethod.slice(0, 16),
    methodSource: e.methodSource,
    isWrite: e.isWrite,
    prefixBytes: e.prefixBytes,
    bodyComplete: e.bodyComplete,
    decodeComplete: e.decodeComplete,
    completeness: { transport: e.completeness.transport, decode: e.completeness.decode, extract: 'none' },
    actions: [],
    status: e.status,
    ...(e.blocked !== undefined && { blocked: truncateUtf8HeadTail(e.blocked, 32) }),
    ...(e.error !== undefined && { error: truncateUtf8HeadTail(e.error, 32) }),
    dispatch: e.dispatch,
    logCapped: true,
  }
}

export function startProxy(
  path: string,
  site: Site,
  key: { key: string; cert: string },
  isLive: () => boolean,
  log: LogRecord[],
  onWrite?: () => void,
  liveGen?: () => number,
  opts?: ProxyV2Options,
): ProxyServer {
  const projection: ProjectionMode = opts?.auditV2?.projection ?? 'semantic'
  const vault = opts?.vault
  const siteName = opts?.siteName ?? (site.start_url ? URL.parse(site.start_url)?.hostname : undefined) ?? site.hosts[0] ?? 'site'
  const sessionId = opts?.sessionId ?? 'session'
  const clientId = opts?.clientId ?? 'default'
  const inFlightTracker = opts?.inFlightTracker ?? new InFlightBudgetTracker()
  const prefixTimeoutMs = opts?.prefixTimeoutMs ?? 10_000
  const streamTimeoutMs = opts?.streamTimeoutMs ?? 30_000
  const maxLogSoftBytes = opts?.maxLogSoftBytes ?? 4 * 1024 * 1024
  const maxLogHardBytes = opts?.maxLogHardBytes ?? 6 * 1024 * 1024
  const maxSampleBytes = opts?.maxSampleBytes ?? 2 * 1024 * 1024
  const collapseGetsAfterBytes = opts?.collapseGetsAfterBytes ?? 1 * 1024 * 1024
  const collapseGetsAfterEntries = opts?.collapseGetsAfterEntries ?? 2_000
  const isLiveNow = opts?.isLiveOrCooldown ?? isLive

  let seqCounter = 0
  let cursorCounter = 0
  let logBytes = 0
  let tailLogBytes = 0
  let reservedBytes = 0
  let sampleBytes = 0
  let droppedGets = 0
  let refusedFullCount = 0
  let incompleteAtSeal = 0
  let droppedLateOutcomes = 0
  let admissionStopped = false
  let sealed = false
  const collapsedGets: Record<string, { count: number; bytes: number }> = {}
  const activeUpstreams = new Set<http.ClientRequest | net.Socket>()
  const activeTunnels = new Set<net.Socket>()
  const activeUpgradeSockets = new Set<net.Socket>()
  const activeInFlight = new Map<number, { finalize: () => void }>()

  const matches = (list: string[], host: string) => list.some(h => h.toLowerCase() === host || h.startsWith('*.') && host.endsWith(h.slice(1).toLowerCase()))
  const isSiteHost = (url: URL | null) => Boolean(url && matches(site.hosts, url.hostname))
  const exact = (host: string) => site.hosts.some(h => h.toLowerCase() === host)
  const allowInternal = (host: string) => {
    if (site.public) return false
    const norm = host.replace(/\.$/, '').toLowerCase()
    return site.internalHosts !== undefined
      ? site.internalHosts.some(h => h.toLowerCase() === norm)
      : exact(norm)
  }
  const via = (host: string) => !!site.via && matches(site.via.hosts, host.replace(/\.$/, ''))
  const origin = site.start_url && new URL(site.start_url).origin
  const secureContext = tls.createSecureContext(key)
  const agents = [0, 1, 2].map(() => ({ 'http:': new http.Agent({ keepAlive: true, autoSelectFamily: false }), 'https:': new https.Agent({ keepAlive: true, autoSelectFamily: false }) }))
  if (site.via) {
    const viaCfg = site.via, proxy = new URL(viaCfg.url)
    if (proxy.protocol !== 'http:' && proxy.protocol !== 'https:') throw new Error('via.url: http://host:port or https://host:port')
    for (const [protocol, agent] of Object.entries(agents[2])) agent.createConnection = (connOpts, cb) => {
      const authority = `${net.isIP(connOpts.host) === 6 ? `[${connOpts.host}]` : connOpts.host}:${connOpts.port}`
      const connect = (proxy.protocol === 'https:' ? https : http).request(proxy, { method: 'CONNECT', path: authority, headers: { host: authority, 'proxy-authorization': `Bearer ${viaCfg.token}` }, agent: false })
      const timer = setTimeout(() => connect.destroy(new Error('upstream proxy CONNECT: no answer in 30s')), 30_000)
      connect.on('connect', (res, socket, head) => {
        clearTimeout(timer)
        if (res.statusCode !== 200) {
          socket.destroy()
          cb(new Error(`upstream proxy CONNECT: ${res.statusCode}`))
          return
        }
        if (head.length) socket.unshift(head)
        cb(null, protocol === 'https:' ? tls.connect({ ...connOpts, socket }) : socket)
      })
      connect.on('error', e => {
        clearTimeout(timer)
        cb(e)
      })
      connect.end()
    }
  }

  const lookup = (strict: boolean) => (host: string, _opts: dns.LookupOptions, cb: (...a: any[]) => void) =>
    dns.lookup(host, { all: true }, (err, addrs) => {
      if (err) return cb(err)
      const ok = addrs.filter(a => !(strict ? isInternal : isNever)(a.address, a.family))
      if (!ok.length) return cb(new Error(`${host} resolves only to ${strict ? 'internal' : 'loopback, link-local or WireServer'} addresses`))
      const one = ok.find(a => a.family === 4) ?? ok[0]
      cb(null, one.address, one.family)
    })

  const urlOf = (req: http.IncomingMessage) => {
    const t = (req.socket as any).target as Target | undefined
    if (t ? !req.url!.startsWith('/') : !/^https?:\/\//.test(req.url!)) return null
    return URL.parse(t ? `${t.scheme}://${t.authority}${req.url}` : req.url!)
  }

  const check = (url: URL | null) => {
    if (!url) return 'malformed request'
    const host = url.hostname
    if ((site.public || site.open) && url.protocol !== 'https:') return 'https only'
    if (site.open && matches(site.except ?? [], host.replace(/\.$/, ''))) return 'host not on the list'
    if (site.open && isBlocked(host)) return 'on a blocklist'
    const ip = host.replace(/^\[(.*)\]$/, '$1')
    if (net.isIP(ip)) return !exact(host) ? 'host not on the list' : !via(host) && (!allowInternal(host) ? isInternal : isNever)(ip, net.isIP(ip)) ? 'internal address' : undefined
    if (!matches(site.hosts, host) && !site.open) return 'host not on the list'
  }

  const buildOutboundSnapshot = (req: http.IncomingMessage, url: URL) => {
    const headers: Record<string, string | string[] | undefined> = { ...req.headers }
    // Normalize site.headers keys to lowercase so mixed-case site overrides replace inbound headers consistently!
    if (url.origin === origin && site.headers) {
      for (const [k, v] of Object.entries(site.headers)) headers[k.toLowerCase()] = v
    }
    headers.host = url.host
    const hadChunked = Boolean(req.headers['transfer-encoding'])
    for (const h of hopByHop) delete headers[h]
    delete headers['expect']
    // Preserve chunked body framing upstream when inbound was chunked without Content-Length (critical for chunked GET/OPTIONS!)
    if (hadChunked && headers['content-length'] === undefined) {
      headers['transfer-encoding'] = 'chunked'
    }
    const strict = !allowInternal(url.hostname)
    return {
      method: req.method,
      headers,
      lookup: lookup(strict),
      agent: agents[via(url.hostname) ? 2 : strict ? 1 : 0][url.protocol as 'http:'],
      servername: net.isIP(url.hostname) ? undefined : url.hostname,
    }
  }

  const classifyArrival = (req: http.IncomingMessage, url: URL | null, effectiveHeaders?: Record<string, string | string[] | undefined>) => {
    const hdrs = effectiveHeaders ?? req.headers
    const sem = classifyMethod(req.method, hdrs)
    const declaredBytes = parseDeclaredBytes(hdrs)
    const hasBodyHint = (declaredBytes ?? 0) > 0 || Boolean(req.headers['transfer-encoding']) || Boolean(hdrs['transfer-encoding'])
    const hasPotentialBody = !SAFE_METHODS.has(sem.wireMethod) || hasBodyHint
    const isWrite = !SAFE_METHODS.has(sem.wireMethod) || sem.hasOverride || hasBodyHint
    const isAuth = url ? isAuthUrl(url) : false
    return { sem, declaredBytes, hasPotentialBody, isWrite, isAuth }
  }

  const applyLateLive = (safe: SafeRequestProjection, liveAtStart: boolean, genAtStart: number | undefined): { safe: SafeRequestProjection; liveAtEnd?: true } => {
    const lateLive = !liveAtStart && (isLiveNow() || (genAtStart !== undefined && liveGen?.() !== genAtStart))
    if (!lateLive) return { safe }
    const copy: SafeRequestProjection = { ...safe }
    if (copy.reqBody !== undefined) {
      delete copy.reqBody
      copy.reqOmitted = 'live'
    }
    return { safe: copy, liveAtEnd: true }
  }

  const normalLimit = () => Math.max(0, maxLogHardBytes - TAIL_RESERVE_BYTES)

  const tryReserveLogSpace = (): number => {
    const avail = normalLimit() - logBytes - reservedBytes
    if (avail < MINIMAL_RESERVE_BYTES) return -1
    const want = logBytes < maxLogSoftBytes && avail >= MAX_ENTRY_BYTES ? MAX_ENTRY_BYTES : MINIMAL_RESERVE_BYTES
    reservedBytes += want
    return want
  }

  const releaseReservation = (amount: number) => {
    if (amount > 0) reservedBytes = Math.max(0, reservedBytes - amount)
  }

  const shouldCollapseGet = (entry: V2Entry): boolean => {
    if (entry.isWrite || entry.blocked || entry.error || entry.kind !== 'http') return false
    if (entry.status < 200 || entry.status >= 400) return false
    if (logBytes < collapseGetsAfterBytes && log.length < collapseGetsAfterEntries) return false
    return STATIC_DESTS.has(entry.dest ?? '') || entry.status === 304 || (logBytes >= maxLogSoftBytes && entry.dest !== 'document')
  }

  const recordCollapsedGet = (draft: V2Entry) => {
    const rawBucket = `${truncateUtf8HeadTail(draft.authority || 'unknown', 48)}:${(draft.dest ?? 'other').slice(0, 12)}`
    const key = rawBucket in collapsedGets || Object.keys(collapsedGets).length < MAX_COLLAPSE_BUCKETS ? rawBucket : '_other'
    const cur = collapsedGets[key] ?? { count: 0, bytes: 0 }
    cur.count++
    cur.bytes += draft.resBytes ?? 0
    collapsedGets[key] = cur
  }

  const appendV2Entry = (entryWithoutN: Omit<V2Entry, 'n'>, ownReservation = 0): number | null => {
    if (sealed) {
      releaseReservation(ownReservation)
      return null
    }
    releaseReservation(ownReservation)

    const draft: V2Entry = { n: cursorCounter + 1, ...entryWithoutN }

    if (shouldCollapseGet(draft)) {
      recordCollapsedGet(draft)
      return null
    }

    // Atomically enforce 2 MiB sample budget at commit time!
    if (draft.reqBody !== undefined) {
      const bLen = Buffer.byteLength(draft.reqBody, 'utf8')
      if (sampleBytes + bLen > maxSampleBytes) {
        delete draft.reqBody
        draft.reqOmitted = 'budget'
      }
    }

    // Account for OTHER concurrent requests' active reservations!
    const avail = normalLimit() - logBytes - reservedBytes
    const isSiteWrite = draft.isWrite && matches(site.hosts, draft.authority.split(':')[0])
    if (!isSiteWrite && !draft.blocked && !draft.error && avail < MINIMAL_RESERVE_BYTES) {
      droppedGets++
      return null
    }

    let finalEntry: V2Entry
    let bytes: number
    if (logBytes >= maxLogSoftBytes) {
      finalEntry = toMinimalCappedEntry(draft)
      bytes = Buffer.byteLength(JSON.stringify(finalEntry), 'utf8')
    } else {
      const capped = capEntryTo12KiB(draft)
      if (capped.bytes <= avail) {
        finalEntry = capped.entry
        bytes = capped.bytes
      } else {
        finalEntry = toMinimalCappedEntry(draft)
        bytes = Buffer.byteLength(JSON.stringify(finalEntry), 'utf8')
      }
    }

    // Strict hard-ceiling guard (even unreserved denials/417s cannot overshoot maxLogHardBytes - TAIL_RESERVE_BYTES)
    if (bytes > avail) {
      if (!isSiteWrite && !finalEntry.blocked && !finalEntry.error) droppedGets++
      else refusedFullCount++
      return null
    }

    if (finalEntry.reqBody !== undefined) {
      sampleBytes += Buffer.byteLength(finalEntry.reqBody, 'utf8')
    }

    finalEntry.n = ++cursorCounter
    const scrubbedEntry = scrubDeep(finalEntry, vault)
    log.push(scrubbedEntry)
    logBytes += bytes
    opts?.onEntry?.(scrubbedEntry)
    return scrubbedEntry.n
  }

  const appendLateOutcome = (rec: Omit<LateOutcomeEntry, 'n'>): void => {
    if (sealed) return
    const preview: LateOutcomeEntry = { n: cursorCounter + 1, ...rec }
    const bytes = Buffer.byteLength(JSON.stringify(preview), 'utf8')
    const summaryFloor = Math.min(8192, Math.floor(TAIL_RESERVE_BYTES / 2))
    if (tailLogBytes + bytes > TAIL_RESERVE_BYTES - summaryFloor) {
      droppedLateOutcomes++
      return
    }
    const full = scrubDeep({ n: ++cursorCounter, ...rec }, vault)
    log.push(full)
    tailLogBytes += bytes
    opts?.onEntry?.(full)
  }

  const buildProjection = async (params: {
    req: http.IncomingMessage
    effectiveHeaders?: Record<string, string | string[] | undefined>
    url: URL | null
    seq: number
    t: string
    kind: 'http' | 'upgrade'
    arrival: ReturnType<typeof classifyArrival>
    liveAtStart: boolean
    genAtStart?: number
    httpCursorAtArrival: number
    cdpCursorAtArrival: number
    prefixBuf?: Buffer
    bodyComplete?: boolean
    transport?: 'complete' | 'truncated' | 'not-read'
    transportReasons?: string[]
    hasBody?: boolean
    fallbackReason?: string
  }): Promise<{ safe: SafeRequestProjection; releaseDecoded: () => void }> => {
    const { req, url, seq, t, kind, arrival, liveAtStart, genAtStart } = params
    const hdrs = params.effectiveHeaders ?? req.headers
    const sanUrl = url ? sanitizeUrl(url, { projection }) : sanitizeUrl(req.url ?? '/', { projection })
    const dest = sanitizeDest(hdrs)
    const from = typeof hdrs.referer === 'string' && hdrs.referer ? sanitizeUrl(hdrs.referer, { projection }).url : undefined
    const prefixBuf = params.prefixBuf ?? Buffer.alloc(0)
    const transport = params.transport ?? 'not-read'
    const bodyComplete = params.bodyComplete ?? false
    const isWrite = arrival.isWrite || (SAFE_METHODS.has(arrival.sem.wireMethod) && (Boolean(params.hasBody) || prefixBuf.length > 0))

    if (params.fallbackReason) {
      return {
        safe: {
          descV: DESC_V,
          redactV: REDACT_V,
          extractorV: EXTRACTOR_V,
          surface: 'browser',
          target: { site: siteName },
          seq,
          t,
          kind,
          scheme: sanUrl.scheme,
          authority: sanUrl.authority,
          path: sanUrl.path,
          url: sanUrl.url,
          method: arrival.sem.wireMethod,
          effectiveMethod: arrival.sem.effectiveMethod,
          methodSource: arrival.sem.methodSource,
          isWrite,
          ...(arrival.sem.hdr && { hdr: arrival.sem.hdr }),
          ...(dest && { dest }),
          ...(from && { from }),
          ...(arrival.declaredBytes !== undefined && { declaredBytes: arrival.declaredBytes }),
          prefixBytes: 0,
          bodyComplete: false,
          decodeComplete: false,
          completeness: { transport: 'not-read', decode: 'none', extract: 'none', reasons: [params.fallbackReason] },
          actions: kind === 'upgrade' ? [{ family: 'upgrade', op: 'upgrade:websocket', resource: sanUrl.path, coverage: 'complete' }] : [],
          cdpCursor: params.cdpCursorAtArrival,
          httpCursor: params.httpCursorAtArrival,
          ...(liveAtStart && { live: true as const }),
        },
        releaseDecoded: () => {},
      }
    }

    const reqType = normalizeContentType(typeof hdrs['content-type'] === 'string' ? hdrs['content-type'] : undefined)
    const liveOrChanged = liveAtStart || isLiveNow() || (genAtStart !== undefined && liveGen?.() !== genAtStart)

    let decodeRes = undefined
    let decodedCharge = 0
    if (kind === 'http' && prefixBuf.length > 0 && !liveOrChanged) {
      const charger = {
        tryAcquire: (b: number) => inFlightTracker.tryAcquire(clientId, sessionId, b),
        release: (b: number) => inFlightTracker.release(clientId, sessionId, b),
      }
      try {
        decodeRes = await decompressPrefix(
          prefixBuf,
          typeof hdrs['content-encoding'] === 'string' ? hdrs['content-encoding'] : undefined,
          bodyComplete,
          MAX_PREFIX_BYTES,
          50,
          charger,
        )
        decodedCharge = decodeRes.chargedBytes ?? 0
      } catch {
        decodeRes = { ok: false, buf: Buffer.alloc(0), decodeComplete: false, decode: 'error' as const, truncated: false, reason: 'decompress-err' }
      }
    }

    const releaseDecoded = () => {
      if (decodedCharge > 0) {
        inFlightTracker.release(clientId, sessionId, decodedCharge)
        decodedCharge = 0
      }
    }

    const liveAfterDecode = liveOrChanged || isLiveNow() || (genAtStart !== undefined && liveGen?.() !== genAtStart)

    const extracted = extractSemantic({
      url: url ?? new URL('http://invalid/'),
      sanitizedPath: sanUrl.path,
      method: arrival.sem.wireMethod,
      effectiveMethod: arrival.sem.effectiveMethod,
      kind,
      hdr: arrival.sem.hdr,
      rawHeaders: hdrs,
      reqType,
      decodedBuf: decodeRes ? decodeRes.buf : prefixBuf,
      decodeResult: decodeRes,
      bodyComplete: transport === 'complete' && bodyComplete,
      transport,
      transportReasons: params.transportReasons ?? [],
      isWrite,
      isAuth: arrival.isAuth,
      isLive: liveAfterDecode,
      projection,
      sampleBudgetOk: sampleBytes < maxSampleBytes,
    })

    const safe: SafeRequestProjection = {
      descV: DESC_V,
      redactV: REDACT_V,
      extractorV: EXTRACTOR_V,
      surface: 'browser',
      target: { site: siteName },
      seq,
      t,
      kind,
      scheme: sanUrl.scheme,
      authority: sanUrl.authority,
      path: sanUrl.path,
      url: sanUrl.url,
      method: arrival.sem.wireMethod,
      effectiveMethod: arrival.sem.effectiveMethod,
      methodSource: arrival.sem.methodSource,
      isWrite,
      ...(arrival.sem.hdr && { hdr: arrival.sem.hdr }),
      ...(dest && { dest }),
      ...(from && { from }),
      ...(reqType && { reqType }),
      ...(arrival.declaredBytes !== undefined && { declaredBytes: arrival.declaredBytes }),
      prefixBytes: prefixBuf.length,
      bodyComplete: transport === 'complete' && bodyComplete,
      decodeComplete: extracted.decodeComplete,
      completeness: extracted.completeness,
      actions: extracted.actions,
      ...(extracted.bodyShape && { bodyShape: extracted.bodyShape }),
      ...(extracted.graphqlOp && { graphqlOp: extracted.graphqlOp }),
      ...(extracted.dupKeys && { dupKeys: true as const }),
      cdpCursor: params.cdpCursorAtArrival,
      httpCursor: params.httpCursorAtArrival,
      ...(liveAtStart && { live: true as const }),
      ...(extracted.reqBody !== undefined && { reqBody: extracted.reqBody }),
      ...(extracted.reqTrunc && { reqTrunc: true as const }),
      ...(extracted.reqOmitted && { reqOmitted: extracted.reqOmitted }),
    }

    return { safe, releaseDecoded }
  }

  const forward = (req: http.IncomingMessage, res: http.ServerResponse) => {
    if (admissionStopped || sealed) {
      res.writeHead(503, { 'content-type': 'text/plain', connection: 'close' }).end('rollforward-browser: session sealed\n')
      return
    }
    const startMs = performance.now()
    const t = new Date().toISOString()
    const url = urlOf(req)
    const seq = ++seqCounter
    const httpCursorAtArrival = cursorCounter
    const cdpCursorAtArrival = opts?.getCdpCursor?.() ?? 0
    const liveAtStart = isLiveNow()
    const genAtStart = liveGen?.()

    vault?.ingestRequestHeaders(req.headers)
    const outboundSnap = url ? buildOutboundSnapshot(req, url) : undefined
    const arrival = classifyArrival(req, url, outboundSnap?.headers)

    const blocked = check(url)
    if (blocked) {
      void buildProjection({
        req, url, seq, t, kind: 'http', arrival, liveAtStart, genAtStart,
        httpCursorAtArrival, cdpCursorAtArrival,
      }).then(({ safe, releaseDecoded }) => {
        releaseDecoded()
        appendV2Entry({ ...safe, status: 403, blocked, dispatch: 'not_dispatched', ms: Math.round(performance.now() - startMs) })
      })
      res.writeHead(403, { 'content-type': 'text/plain' }).end(`rollforward-browser: ${blocked}: ${req.method} ${url?.href ?? req.url}\n`)
      return
    }

    let reserved = 0
    if (arrival.isWrite && isSiteHost(url)) {
      reserved = tryReserveLogSpace()
      if (reserved < 0) {
        refusedFullCount++
        res.writeHead(403, { 'content-type': 'application/json', connection: 'close' }).end(JSON.stringify({ error: 'audit log full' }))
        return
      }
    }

    // 1. Bounded 64 KiB prefix tee
    const teeChunks: Buffer[] = []
    let teeLen = 0
    let teeAcquired = 0
    let teeFrozen = !arrival.hasPotentialBody
    let teeComplete = false
    let teeTransport: 'complete' | 'truncated' | 'not-read' = arrival.hasPotentialBody ? 'truncated' : 'not-read'
    const teeReasons: string[] = []
    let totalReqBytes = 0
    let budgetHit = false
    let prefixTimer: NodeJS.Timeout | undefined
    let builtPromise: Promise<{ safe: SafeRequestProjection; releaseDecoded: () => void }> | undefined
    let resolvedBuilt: { safe: SafeRequestProjection; releaseDecoded: () => void } | undefined
    let teeReleased = false

    const releaseTee = () => {
      clearTimeout(prefixTimer)
      if (teeReleased) return
      teeReleased = true
      if (teeAcquired > 0) {
        inFlightTracker.release(clientId, sessionId, teeAcquired)
        teeAcquired = 0
      }
      teeChunks.length = 0
      resolvedBuilt?.releaseDecoded()
    }

    const startBuild = () => {
      if (builtPromise) return builtPromise
      const prefixBuf = teeChunks.length === 1 ? teeChunks[0] : Buffer.concat(teeChunks)
      teeChunks.length = 0
      builtPromise = buildProjection({
        req, effectiveHeaders: outboundSnap?.headers, url, seq, t, kind: 'http',
        arrival, liveAtStart, genAtStart, httpCursorAtArrival, cdpCursorAtArrival,
        prefixBuf, bodyComplete: teeComplete, transport: teeTransport, transportReasons: teeReasons,
        hasBody: totalReqBytes > 0,
      }).then(built => {
        resolvedBuilt = built
        if (budgetHit && built.safe.isWrite && (!built.safe.reqOmitted || built.safe.reqOmitted === 'policy-profile')) {
          built.safe.reqOmitted = 'budget'
        }
        if (sealed || teeReleased) {
          built.releaseDecoded()
          releaseTee()
        }
        return built
      })
      return builtPromise
    }

    const freezeTee = (complete: boolean, reason?: string) => {
      if (teeFrozen) return
      teeFrozen = true
      clearTimeout(prefixTimer)
      teeComplete = complete
      teeTransport = complete ? 'complete' : 'truncated'
      if (reason && !teeReasons.includes(reason)) teeReasons.push(reason)
      if (!sealed) void startBuild().catch(() => {})
    }

    if (arrival.hasPotentialBody) {
      prefixTimer = setTimeout(() => freezeTee(false, 'prefix-timeout'), prefixTimeoutMs)
      prefixTimer.unref()
    } else {
      void startBuild().catch(() => {})
    }

    req.on('data', (chunk: Buffer) => {
      totalReqBytes += chunk.length
      if (!arrival.hasPotentialBody && teeTransport === 'not-read') {
        teeFrozen = false
        teeComplete = false
        teeTransport = 'truncated'
      }
      if (teeFrozen) return
      if (teeLen >= MAX_PREFIX_BYTES) return freezeTee(false, '>64KiB')
      const take = Math.min(chunk.length, MAX_PREFIX_BYTES - teeLen)
      if (!inFlightTracker.tryAcquire(clientId, sessionId, take)) {
        budgetHit = true
        return freezeTee(false, 'budget')
      }
      teeAcquired += take
      teeChunks.push(Buffer.from(chunk.subarray(0, take)))
      teeLen += take
      if (chunk.length > take) freezeTee(false, '>64KiB')
      else if (teeLen === MAX_PREFIX_BYTES) freezeTee(req.readableEnded, req.readableEnded ? undefined : '>=64KiB')
    })
    req.on('end', () => { if (!teeFrozen) freezeTee(true) })

    // 2. Dispatch upstream + single finalize-once path + seal hook
    let resBytes = 0
    let status = 0
    let resType: string | undefined
    let headerMs: number | undefined
    let errorMsg: string | undefined
    let emitStarted = false
    let committed = false
    let emittedN: number | null = null
    let timedOutStream = false
    let reqDone = req.readableEnded || !arrival.hasPotentialBody
    let resDone = false
    let lateEmitted = false
    const pendingLate: Array<Omit<LateOutcomeEntry, 'n' | 'ref'>> = []

    const flushPendingLate = () => {
      if (emittedN === null || sealed) return
      while (pendingLate.length) appendLateOutcome({ ...pendingLate.shift()!, ref: emittedN })
    }

    const commit = (safe: SafeRequestProjection, extra: { incomplete?: true; forceDispatch?: 'unknown' }) => {
      if (committed) return
      committed = true
      activeInFlight.delete(seq)
      const ms = Math.round(performance.now() - startMs)
      const ll = applyLateLive(safe, liveAtStart, genAtStart)
      const scrubbedErr = errorMsg ? scrubText(errorMsg).text : undefined
      const ownRes = reserved
      reserved = 0
      emittedN = appendV2Entry({
        ...ll.safe,
        status,
        ...(scrubbedErr && { error: scrubbedErr }),
        ...(resType && { resType }),
        reqBytes: totalReqBytes,
        resBytes,
        ...(headerMs !== undefined && { headerMs }),
        ms,
        dispatch: extra.forceDispatch ?? 'dispatched',
        ...(ll.liveAtEnd && { liveAtEnd: true as const }),
        ...(extra.incomplete && { incomplete: true as const }),
      }, ownRes)
      flushPendingLate()
    }

    const finalizeOnce = (extra: { incomplete?: true }) => {
      if (emitStarted || committed) return
      emitStarted = true
      clearTimeout(streamTimer)
      if (!teeFrozen) freezeTee(req.readableEnded)
      void startBuild().then(
        built => { commit(built.safe, extra); releaseTee() },
        async () => {
          const { safe } = await buildProjection({
            req, url, seq, t, kind: 'http', arrival, liveAtStart, genAtStart,
            httpCursorAtArrival, cdpCursorAtArrival, fallbackReason: 'extractor-error',
          })
          commit(safe, extra)
          releaseTee()
        },
      )
    }

    const emitLate = (incomplete?: true) => {
      if (!timedOutStream || !emitStarted || lateEmitted || sealed) return
      lateEmitted = true
      const scrubbedErr = errorMsg ? scrubText(errorMsg).text : undefined
      const rec: Omit<LateOutcomeEntry, 'n' | 'ref'> = {
        rec: 'http_end',
        t: new Date().toISOString(),
        reqBytes: totalReqBytes,
        resBytes,
        ms: Math.round(performance.now() - startMs),
        ...(scrubbedErr && { error: scrubbedErr }),
        ...(incomplete && { incomplete: true as const }),
      }
      if (emittedN !== null) appendLateOutcome({ ...rec, ref: emittedN })
      else pendingLate.push(rec)
    }

    const tryComplete = () => {
      if (reqDone && resDone) {
        if (!emitStarted) finalizeOnce({})
        else emitLate()
      }
    }

    const streamTimer = setTimeout(() => {
      if (!emitStarted && !(reqDone && resDone)) {
        timedOutStream = true
        finalizeOnce({ incomplete: true })
      }
    }, streamTimeoutMs)
    streamTimer.unref()

    // 3. Register synchronous seal finalizer
    activeInFlight.set(seq, {
      finalize: () => {
        if (committed) return
        incompleteAtSeal++
        clearTimeout(streamTimer)
        const fallbackSafe = resolvedBuilt?.safe ?? (() => {
          const sanUrl = url ? sanitizeUrl(url, { projection }) : sanitizeUrl(req.url ?? '/', { projection })
          return {
            descV: DESC_V, redactV: REDACT_V, extractorV: EXTRACTOR_V,
            surface: 'browser' as const, target: { site: siteName }, seq, t, kind: 'http' as const,
            scheme: sanUrl.scheme, authority: sanUrl.authority, path: sanUrl.path, url: sanUrl.url,
            method: arrival.sem.wireMethod, effectiveMethod: arrival.sem.effectiveMethod, methodSource: arrival.sem.methodSource,
            isWrite: arrival.isWrite,
            ...(arrival.sem.hdr && { hdr: arrival.sem.hdr }),
            ...(sanitizeDest(req.headers) && { dest: sanitizeDest(req.headers) }),
            prefixBytes: 0, bodyComplete: false, decodeComplete: false,
            completeness: { transport: 'not-read' as const, decode: 'none' as const, extract: 'none' as const, reasons: ['sealed-in-flight'] },
            actions: [], cdpCursor: cdpCursorAtArrival, httpCursor: httpCursorAtArrival,
            ...(liveAtStart && { live: true as const }),
          }
        })()
        releaseTee()
        commit(fallbackSafe, { incomplete: true, forceDispatch: 'unknown' })
      },
    })

    const up = (url!.protocol === 'https:' ? https : http).request(url!, outboundSnap!, r => {
      headerMs = Math.round(performance.now() - startMs)
      status = r.statusCode ?? 0
      vault?.ingestSetCookie(r.headers['set-cookie'])
      resType = normalizeContentType(r.headers['content-type'])

      const headers = { ...r.headers }
      for (const h of hopByHop) delete headers[h]
      if (!res.destroyed) {
        res.writeHead(status, headers)
        r.pipe(res)
      }

      r.on('data', (c: Buffer) => { resBytes += c.length })
      r.on('end', () => {
        resDone = true
        tryComplete()
        const dest = typeof req.headers['sec-fetch-dest'] === 'string' ? req.headers['sec-fetch-dest'] : undefined
        if (!liveAtStart && arrival.isWrite && !isLiveNow() && liveGen?.() === genAtStart) {
          opts?.onWriteDetail?.({ dest, isWrite: true })
          if (!opts?.onWriteDetail) onWrite?.()
        }
      })
      r.on('aborted', () => {
        resDone = true; reqDone = true
        errorMsg ||= 'upstream response aborted'
        if (!emitStarted) finalizeOnce({ incomplete: true })
        else emitLate(true)
      })
      r.on('error', e => {
        resDone = true; reqDone = true
        errorMsg ||= e.message
        if (!emitStarted) finalizeOnce({ incomplete: true })
        else emitLate(true)
        if (!res.destroyed) res.destroy()
      })
    })
    activeUpstreams.add(up)
    up.on('close', () => activeUpstreams.delete(up))

    const onCancel = () => {
      if (reqDone && resDone) return
      reqDone = true; resDone = true
      up.destroy()
      if (!emitStarted) finalizeOnce({ incomplete: true })
      else emitLate(true)
    }
    req.on('error', onCancel)
    res.on('close', () => { if (!res.writableFinished) onCancel() })

    up.on('error', e => {
      reqDone = true; resDone = true
      errorMsg ||= e.message
      if (status === 0) status = 502
      if (!emitStarted) finalizeOnce({})
      else emitLate(true)
      if (!res.headersSent && !res.destroyed) {
        res.writeHead(502, { 'content-type': 'text/plain' }).end(`rollforward-browser: ${e.message}\n`)
      } else if (!res.destroyed) {
        res.destroy()
      }
    })

    if (!reqDone) req.once('end', () => { reqDone = true; tryComplete() })
    req.pipe(up)
  }

  const forwardUpgrade = (req: http.IncomingMessage, socket: net.Socket, head: Buffer) => {
    socket.on('error', () => socket.destroy())
    if (admissionStopped || sealed) {
      socket.end('HTTP/1.1 503 Service Unavailable\r\nconnection: close\r\n\r\n')
      return
    }
    activeUpgradeSockets.add(socket)
    socket.once('close', () => activeUpgradeSockets.delete(socket))
    const startMs = performance.now()
    const t = new Date().toISOString()
    const url = urlOf(req)
    const seq = ++seqCounter
    const httpCursorAtArrival = cursorCounter
    const cdpCursorAtArrival = opts?.getCdpCursor?.() ?? 0
    const liveAtStart = isLiveNow()
    const genAtStart = liveGen?.()

    vault?.ingestRequestHeaders(req.headers)
    const outboundSnap = url ? buildOutboundSnapshot(req, url) : undefined
    const arrival = classifyArrival(req, url, outboundSnap?.headers)

    let committed = false
    let reserved = 0
    let dispatchState: 'not_dispatched' | 'dispatched' | 'unknown' = 'not_dispatched'

    const commitUpgrade = (safe: SafeRequestProjection, extra: { status: number; blocked?: string; error?: string; dispatch?: 'not_dispatched' | 'dispatched' | 'unknown'; incomplete?: true }) => {
      if (committed) return
      committed = true
      activeInFlight.delete(seq)
      const ll = applyLateLive(safe, liveAtStart, genAtStart)
      const ownRes = reserved
      reserved = 0
      appendV2Entry({
        ...ll.safe,
        status: extra.status,
        ...(extra.blocked && { blocked: extra.blocked }),
        ...(extra.error && { error: extra.error }),
        dispatch: extra.dispatch ?? dispatchState,
        ...(ll.liveAtEnd && { liveAtEnd: true as const }),
        ...(extra.incomplete && { incomplete: true as const }),
        ms: Math.round(performance.now() - startMs),
      }, ownRes)
    }

    void buildProjection({
      req, effectiveHeaders: outboundSnap?.headers, url, seq, t, kind: 'upgrade',
      arrival, liveAtStart, genAtStart, httpCursorAtArrival, cdpCursorAtArrival,
    }).then(({ safe, releaseDecoded }) => {
      releaseDecoded()
      const blocked = check(url)
      if (blocked) {
        commitUpgrade(safe, { status: 403, blocked, dispatch: 'not_dispatched' })
        socket.end('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n')
        return
      }
      if (arrival.isWrite && isSiteHost(url)) {
        reserved = tryReserveLogSpace()
        if (reserved < 0) {
          reserved = 0
          committed = true
          refusedFullCount++
          const fullJson = JSON.stringify({ error: 'audit log full' })
          socket.end(`HTTP/1.1 403 Forbidden\r\ncontent-type: application/json\r\ncontent-length: ${Buffer.byteLength(fullJson)}\r\nconnection: close\r\n\r\n${fullJson}`)
          return
        }
      }
      if (socket.destroyed || sealed || admissionStopped) {
        commitUpgrade(safe, { status: 0, dispatch: 'not_dispatched', incomplete: true })
        socket.destroy()
        return
      }

      activeInFlight.set(seq, {
        finalize: () => {
          if (committed) return
          incompleteAtSeal++
          commitUpgrade(safe, { status: 0, dispatch: dispatchState === 'dispatched' ? 'unknown' : 'not_dispatched', incomplete: true })
        },
      })

      const uOpts = outboundSnap!
      uOpts.headers.connection = 'upgrade'
      uOpts.headers.upgrade = req.headers.upgrade
      const up = (url!.protocol === 'https:' ? https : http).request(url!, uOpts)
      dispatchState = 'dispatched'
      activeUpstreams.add(up)
      const destroyUp = () => up.destroy()
      if (socket.destroyed) { up.destroy(); return }
      socket.once('close', destroyUp)
      up.on('close', () => { activeUpstreams.delete(up); socket.off('close', destroyUp) })
      up.on('upgrade', (r, upSocket, upHead) => {
        if (socket.destroyed || sealed) { upSocket.destroy(); return }
        activeUpstreams.add(upSocket)
        const destroyUpSock = () => upSocket.destroy()
        upSocket.on('close', () => { activeUpstreams.delete(upSocket); socket.off('close', destroyUpSock) })
        upSocket.on('error', () => socket.destroy())
        socket.once('close', destroyUpSock)
        vault?.ingestSetCookie(r.headers['set-cookie'])
        commitUpgrade(safe, { status: 101, dispatch: 'dispatched' })
        socket.write(`HTTP/1.1 101 Switching Protocols\r\n${Object.entries(r.headers).map(([k, v]) => `${k}: ${v}\r\n`).join('')}\r\n`)
        upSocket.write(head)
        socket.write(upHead)
        upSocket.pipe(socket).pipe(upSocket)
      })
      up.on('response', r => {
        r.resume()
        commitUpgrade(safe, { status: r.statusCode ?? 0, dispatch: 'dispatched' })
        socket.end(`HTTP/1.1 ${r.statusCode} ${r.statusMessage}\r\nconnection: close\r\n\r\n`)
      })
      up.on('error', e => {
        commitUpgrade(safe, { status: 502, error: scrubText(e.message).text, dispatch: 'dispatched' })
        socket.end('HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n')
      })
      up.end()
    }).catch(() => {
      activeInFlight.get(seq)?.finalize()
      socket.destroy()
    })
  }

  const handleContinue = (req: http.IncomingMessage, res: http.ServerResponse) => {
    if (admissionStopped || sealed) {
      res.writeHead(503, { 'content-type': 'text/plain', connection: 'close' }).end('rollforward-browser: session sealed\n')
      return
    }
    const url = urlOf(req)
    const blocked = check(url)
    if (blocked) {
      forward(req, res)
      return
    }
    res.writeContinue()
    forward(req, res)
  }

  const handleExpectation = (req: http.IncomingMessage, res: http.ServerResponse) => {
    const url = urlOf(req)
    const seq = ++seqCounter
    const arrival = classifyArrival(req, url)
    void buildProjection({
      req, url, seq, t: new Date().toISOString(), kind: 'http', arrival,
      liveAtStart: isLiveNow(), httpCursorAtArrival: cursorCounter, cdpCursorAtArrival: opts?.getCdpCursor?.() ?? 0,
      fallbackReason: 'expectation-failed',
    }).then(({ safe }) => {
      appendV2Entry({ ...safe, status: 417, blocked: 'expectation failed', dispatch: 'not_dispatched' })
    })
    res.writeHead(417, { 'content-type': 'text/plain', connection: 'close' }).end('rollforward-browser: 417 Expectation Failed\n')
  }

  const inner = http.createServer(forward)
  inner.on('upgrade', forwardUpgrade)
  inner.on('checkContinue', handleContinue)
  inner.on('checkExpectation', handleExpectation)

  const outer = http.createServer(forward) as ProxyServer
  outer.on('upgrade', forwardUpgrade)
  outer.on('checkContinue', handleContinue)
  outer.on('checkExpectation', handleExpectation)
  outer.on('connect', (req: http.IncomingMessage, socket: net.Socket, head: Buffer) => {
    if (admissionStopped || sealed) {
      socket.end('HTTP/1.1 503 Service Unavailable\r\nconnection: close\r\n\r\n')
      return
    }
    activeTunnels.add(socket)
    socket.on('close', () => activeTunnels.delete(socket))
    socket.on('error', () => socket.destroy())
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
    const start = (first: Buffer) => {
      if (admissionStopped || sealed) return socket.destroy()
      socket.pause()
      socket.unshift(first)
      const s = first[0] === 0x16 ? new tls.TLSSocket(socket, { isServer: true, secureContext, ALPNProtocols: ['http/1.1'] }) : plain(socket)
      ;(s as any).target = { scheme: first[0] === 0x16 ? 'https' : 'http', authority: req.url! } satisfies Target
      inner.emit('connection', s)
    }
    head.length ? start(head) : socket.once('data', start)
  })
  outer.on('close', () => {
    inner.close()
    inner.closeAllConnections?.()
    agents.forEach(pool => Object.values(pool).forEach(a => a.destroy()))
  })

  const stopAdmission = () => {
    if (admissionStopped) return
    admissionStopped = true
    outer.close()
    outer.closeAllConnections()
    inner.close()
    inner.closeAllConnections()
    for (const sock of activeTunnels) sock.destroy()
    activeTunnels.clear()
    for (const sock of activeUpgradeSockets) sock.destroy()
    activeUpgradeSockets.clear()
    for (const up of activeUpstreams) up.destroy()
    activeUpstreams.clear()
  }

  outer.controller = {
    stopAdmission,
    finalizeAtSeal: () => {
      if (sealed) return { logCursor: cursorCounter, droppedGets, refusedFull: refusedFullCount }
      admissionStopped = true
      outer.close()
      inner.close()
      for (const item of [...activeInFlight.values()]) item.finalize()
      activeInFlight.clear()
      const summary: SummaryEntry = {
        n: ++cursorCounter,
        rec: '_summary',
        t: new Date().toISOString(),
        collapsedGets: { ...collapsedGets },
        droppedGets,
        refusedFullCount,
        incompleteAtSeal,
        ...(droppedLateOutcomes > 0 && { droppedLateOutcomes }),
      }
      log.push(summary)
      tailLogBytes += Buffer.byteLength(JSON.stringify(summary), 'utf8')
      sealed = true
      outer.closeAllConnections?.()
      inner.closeAllConnections?.()
      for (const sock of activeTunnels) sock.destroy()
      activeTunnels.clear()
      for (const sock of activeUpgradeSockets) sock.destroy()
      activeUpgradeSockets.clear()
      for (const up of activeUpstreams) up.destroy()
      activeUpstreams.clear()
      return { logCursor: cursorCounter, droppedGets, refusedFull: refusedFullCount }
    },
    getLogPage: (after: number, limit = 500) => {
      const cappedLimit = Math.min(500, Math.max(1, limit))
      const oldestCursor = log.length ? log[0].n : cursorCounter
      const out: LogRecord[] = []
      let pageBytes = 128
      let lastIdx = -1
      for (let i = 0; i < log.length; i++) {
        const e = log[i]
        if (e.n <= after) continue
        const size = Buffer.byteLength(JSON.stringify(e), 'utf8') + 1
        if (out.length > 0 && (out.length >= cappedLimit || pageBytes + size > MAX_PAGE_BYTES)) break
        out.push(e)
        pageBytes += size
        lastIdx = i
      }
      const hasMore = lastIdx >= 0 && lastIdx < log.length - 1
      const nextCursor = out.length > 0 ? out[out.length - 1].n : Math.max(after, oldestCursor)
      return { oldestCursor, nextCursor, hasMore, dropped: droppedGets, entries: out }
    },
    getCurrentCursor: () => cursorCounter,
    clear: () => {
      log.length = 0
      logBytes = 0
      tailLogBytes = 0
      reservedBytes = 0
      sampleBytes = 0
    },
  }

  outer.listen(path)
  return outer
}
