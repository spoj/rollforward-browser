import crypto from 'node:crypto'
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
  scrubText,
  truncateHeadTail,
  type ProjectionMode,
} from './redact.ts'

export const DESC_V = 1

export type AuditV2Config = {
  v: 2
  projection?: ProjectionMode
  cdp?: boolean
  hud?: boolean
  intent?: { run: number; series?: string; taskSummary?: string }
}

export type PolicyDecision = {
  decisionId: string
  mode: 'observe' | 'shadow' | 'enforce'
  stage: 1 | 2
  action: 'allow' | 'deny' | 'escalate' | 'requireApproval'
  ruleId: string
  policyVersion: string
  ms: number
  approvalRef?: string
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
  hdrConflict?: true
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
  vaultRedactions?: number
  cdpCursor?: number
  httpCursor?: number
  siteConfigRev?: number
  live?: true
  reqBody?: string
  reqTrunc?: true
  reqOmitted?: BodyOmittedReason
}

export type LegacyEntry = {
  t: string
  method: string
  url: string
  status: number
  dest?: string
  from?: string
  blocked?: string
  error?: string
  live?: true
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
  policy?: PolicyDecision
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
  policy?: PolicyDecision
}

export type SummaryEntry = {
  n: number
  rec: '_summary'
  t: string
  collapsedGets: Record<string, { count: number; bytes: number }>
  droppedGets: number
  refusedFullCount: number
  incompleteAtSeal: number
}

export type LogRecord = LegacyEntry | V2Entry | LateOutcomeEntry | SummaryEntry
export type Entry = LegacyEntry & Partial<V2Entry>

export type RequestDescriptor = {
  safe: SafeRequestProjection
  raw?: {
    url: string
    parsedBody?: unknown
    rawBodyText?: string
    declaredBytes?: number
  }
}

export type PolicyContext = {
  decisionId: string
  signal: AbortSignal
  deadlineMs: number
  intent?: AuditV2Config['intent']
  recentCdpCursor?: number
  recentHttpCursor?: number
}

export type PolicyHookConfig = {
  mode: 'shadow' | 'enforce'
  liveMode?: 'enforce' | 'shadow' | 'allow'
  deadlineMs?: number
  evaluate: (d: RequestDescriptor, ctx: PolicyContext) => PolicyDecision | Promise<PolicyDecision>
}

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
  policyHook?: PolicyHookConfig
  getSiteConfigRev?: () => number
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
  maxConcurrentAsyncHooks?: number
}

export type ProxyController = {
  finalizeAtSeal: () => { logCursor: number; droppedGets: number; refusedFull: number }
  getLogPage: (after: number, limit?: number) => {
    oldestCursor: number
    nextCursor: number
    hasMore: boolean
    dropped: number
    entries: LogRecord[]
  }
  getCurrentCursor: () => number
  getRetainedBytes: () => number
  clear: () => void
}

export type ProxyServer = http.Server & { controller: ProxyController }

// `public`, for a person's own site rather than one an admin set up: no direct connection, exact hosts included, reaches an
// internal address, and it goes over https only.
export type Site = { hosts: string[], start_url?: string, headers?: Record<string, string>, public?: boolean, open?: boolean, except?: string[], via?: { url: string, token: string, hosts: string[] } }
type Target = { scheme: string, authority: string }

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const OVERRIDE_HEADERS = ['x-http-method', 'x-http-method-override', 'x-method-override'] as const
const VALID_VERB_RE = /^[A-Z]{3,16}$/
const STATIC_DESTS = new Set(['image', 'font', 'style', 'script', 'audio', 'video'])

const MAX_ENTRY_BYTES = 12 * 1024
const MINIMAL_RESERVE_BYTES = 512
const TAIL_RESERVE_BYTES = 64 * 1024
const MAX_PAGE_BYTES = 4 * 1024 * 1024

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

export function toLegacyLog(entries: LogRecord[]): LegacyEntry[] {
  const out: LegacyEntry[] = []
  for (const e of entries) {
    const rec = (e as any).rec
    if (rec === '_summary' || rec === 'http_end') continue
    const le = e as LegacyEntry
    out.push({
      t: le.t,
      method: le.method,
      url: le.url,
      status: le.status,
      ...(le.dest !== undefined && { dest: le.dest }),
      ...(le.from !== undefined && { from: le.from }),
      ...(le.blocked !== undefined && { blocked: le.blocked }),
      ...(le.error !== undefined && { error: le.error }),
      ...(le.live && { live: true as const }),
    })
  }
  return out
}

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

function parseSemanticMethods(
  req: http.IncomingMessage,
  vault?: SecretVault,
): {
  wireMethod: string
  effectiveMethod: string
  methodSource: SafeRequestProjection['methodSource']
  hdr?: Record<string, string>
  hdrConflict: boolean
  invalidOrConflictingOverride: boolean
  vaultRedactions: number
} {
  const wireMethod = (req.method ?? 'GET').toUpperCase()
  const hdr: Record<string, string> = {}
  let vaultRedactions = 0
  let invalid = false
  const validTokens: Array<{ header: typeof OVERRIDE_HEADERS[number]; verb: string }> = []

  for (const name of OVERRIDE_HEADERS) {
    const rawVal = req.headers[name]
    if (rawVal === undefined) continue
    const joined = Array.isArray(rawVal) ? rawVal.join(',') : rawVal
    const scrubbed = scrubText(joined.slice(0, 256), vault)
    vaultRedactions += scrubbed.vaultRedactions
    hdr[name] = scrubbed.text

    const parts = joined.split(',').map(p => p.trim().toUpperCase()).filter(Boolean)
    if (!parts.length) {
      invalid = true
      continue
    }
    for (const p of parts) {
      if (!VALID_VERB_RE.test(p)) invalid = true
      else validTokens.push({ header: name, verb: p })
    }
  }

  const soapRaw = req.headers['soapaction']
  if (soapRaw !== undefined) {
    const joined = Array.isArray(soapRaw) ? soapRaw.join(',') : soapRaw
    const scrubbed = scrubText(joined.slice(0, 256), vault)
    vaultRedactions += scrubbed.vaultRedactions
    hdr.soapaction = scrubbed.text
  }

  const distinctVerbs = [...new Set(validTokens.map(v => v.verb))]
  const hdrConflict = distinctVerbs.length > 1
  const invalidOrConflictingOverride = invalid || hdrConflict

  let effectiveMethod = wireMethod
  let methodSource: SafeRequestProjection['methodSource'] = 'wire'

  if (validTokens.length > 0) {
    // Find first unsafe verb if any; override may ONLY escalate safe -> unsafe or write -> another write, NEVER downgrade write -> read!
    const unsafe = validTokens.find(v => !SAFE_METHODS.has(v.verb))
    if (unsafe) {
      effectiveMethod = unsafe.verb
      methodSource = unsafe.header
    } else if (SAFE_METHODS.has(wireMethod)) {
      // Safe wire + safe override(s): keep wireMethod unless conflict/invalid (handled via isWrite)
      effectiveMethod = validTokens[0].verb
      methodSource = validTokens[0].header
    } else {
      // Unsafe wire + safe override (e.g. POST + X-HTTP-Method-Override: GET): NEVER downgrade!
      effectiveMethod = wireMethod
      methodSource = 'wire'
    }
  }

  return {
    wireMethod,
    effectiveMethod,
    methodSource,
    hdr: Object.keys(hdr).length ? hdr : undefined,
    hdrConflict,
    invalidOrConflictingOverride,
    vaultRedactions,
  }
}

function parseDeclaredBytes(req: http.IncomingMessage): number | undefined {
  const cl = req.headers['content-length']
  if (typeof cl !== 'string') return undefined
  const n = Number(cl.trim())
  return Number.isInteger(n) && n >= 0 ? n : undefined
}

function capEntryTo12KiB(entry: V2Entry): { entry: V2Entry; bytes: number } {
  let s = JSON.stringify(entry)
  let bytes = Buffer.byteLength(s)
  if (bytes <= MAX_ENTRY_BYTES) return { entry, bytes }

  const copy: V2Entry = { ...entry }
  if (copy.reqBody !== undefined) {
    const excess = bytes - MAX_ENTRY_BYTES + 128
    const targetLen = Math.max(0, copy.reqBody.length - excess)
    if (targetLen <= 64) {
      delete copy.reqBody
      copy.reqTrunc = true
    } else {
      copy.reqBody = truncateHeadTail(copy.reqBody, targetLen, Math.floor(targetLen * 0.75), Math.floor(targetLen * 0.25))
      copy.reqTrunc = true
    }
    s = JSON.stringify(copy)
    bytes = Buffer.byteLength(s)
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
    s = JSON.stringify(copy)
    bytes = Buffer.byteLength(s)
    if (bytes <= MAX_ENTRY_BYTES) return { entry: copy, bytes }
  }

  if (copy.actions.length) {
    copy.actions = copy.actions.slice(0, 4).map(a => ({ family: a.family, op: a.op, ...(a.resource && { resource: a.resource.slice(0, 256) }), coverage: a.coverage }))
    s = JSON.stringify(copy)
    bytes = Buffer.byteLength(s)
    if (bytes <= MAX_ENTRY_BYTES) return { entry: copy, bytes }
  }

  // Final deterministic fallback: minimal record preserving origin + pathname
  const minimal = toMinimalCappedEntry(copy)
  return { entry: minimal, bytes: Buffer.byteLength(JSON.stringify(minimal)) }
}

function toMinimalCappedEntry(e: V2Entry): V2Entry {
  const originPath = e.authority ? `${e.scheme}://${e.authority}${e.path.slice(0, 160)}` : e.url.slice(0, 160)
  return {
    n: e.n,
    descV: DESC_V,
    redactV: REDACT_V,
    extractorV: EXTRACTOR_V,
    surface: e.surface,
    target: e.target,
    seq: e.seq,
    t: e.t,
    kind: e.kind,
    scheme: e.scheme,
    authority: e.authority,
    path: e.path.slice(0, 160),
    url: originPath,
    method: e.method,
    effectiveMethod: e.effectiveMethod,
    methodSource: e.methodSource,
    isWrite: e.isWrite,
    prefixBytes: e.prefixBytes,
    bodyComplete: e.bodyComplete,
    decodeComplete: e.decodeComplete,
    completeness: { transport: e.completeness.transport, decode: e.completeness.decode, extract: 'none' },
    actions: [],
    status: e.status,
    ...(e.blocked !== undefined && { blocked: e.blocked.slice(0, 80) }),
    ...(e.error !== undefined && { error: e.error.slice(0, 80) }),
    dispatch: e.dispatch,
    ...(e.live && { live: true as const }),
    ...(e.incomplete && { incomplete: true as const }),
    logCapped: true,
  }
}

type PrefixReadResult = {
  prefixBuf: Buffer
  overflowChunks: Buffer[]
  bodyComplete: boolean
  transport: 'complete' | 'truncated'
  reasons: string[]
  totalReadBytes: number
  aborted: boolean
  budgetExceeded: boolean
  releaseBudget: () => void
  onEndFlag: () => boolean
}

// Single-owner bounded PrefixReader for enforce-mode writes.
function readBoundedPrefix(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  tracker: InFlightBudgetTracker,
  clientId: string,
  sessionId: string,
  prefixTimeoutMs: number,
  abortController: AbortController,
): Promise<PrefixReadResult> {
  return new Promise(resolve => {
    const prefixChunks: Buffer[] = []
    const overflowChunks: Buffer[] = []
    let prefixLen = 0
    let totalReadBytes = 0
    let acquiredBytes = 0
    let settled = false
    let reqEnded = req.readableEnded
    const reasons: string[] = []

    const releaseBudget = () => {
      if (acquiredBytes > 0) {
        tracker.release(clientId, sessionId, acquiredBytes)
        acquiredBytes = 0
      }
    }

    const cleanup = () => {
      clearTimeout(timer)
      req.off('data', onData)
      req.off('end', onEnd)
      req.off('error', onError)
      res.off('close', onResClose)
    }

    const done = (resObj: Omit<PrefixReadResult, 'prefixBuf' | 'overflowChunks' | 'reasons' | 'totalReadBytes' | 'releaseBudget' | 'onEndFlag'>) => {
      if (settled) return
      settled = true
      cleanup()
      resolve({
        prefixBuf: Buffer.concat(prefixChunks),
        overflowChunks,
        reasons,
        totalReadBytes,
        releaseBudget,
        onEndFlag: () => reqEnded || req.readableEnded,
        ...resObj,
      })
    }

    // Persistent listener so we know if 'end' arrived while paused/draining
    const markEnded = () => { reqEnded = true }
    req.once('end', markEnded)

    const onResClose = () => {
      if (!res.writableFinished) {
        abortController.abort()
        req.pause()
        done({ bodyComplete: false, transport: 'truncated', aborted: true, budgetExceeded: false })
      }
    }
    const onError = () => {
      abortController.abort()
      done({ bodyComplete: false, transport: 'truncated', aborted: true, budgetExceeded: false })
    }
    const onEnd = () => {
      reqEnded = true
      done({ bodyComplete: true, transport: 'complete', aborted: false, budgetExceeded: false })
    }
    const onData = (chunk: Buffer) => {
      if (settled) return
      totalReadBytes += chunk.length
      if (!tracker.tryAcquire(clientId, sessionId, chunk.length)) {
        req.pause()
        done({ bodyComplete: false, transport: 'truncated', aborted: false, budgetExceeded: true })
        return
      }
      acquiredBytes += chunk.length
      if (prefixLen + chunk.length < MAX_PREFIX_BYTES) {
        prefixChunks.push(chunk)
        prefixLen += chunk.length
        return
      }
      if (prefixLen + chunk.length === MAX_PREFIX_BYTES) {
        prefixChunks.push(chunk)
        prefixLen = MAX_PREFIX_BYTES
        // Exact 64 KiB boundary: pause immediately (never block on a paused stream); complete only if readableEnded already true.
        if (req.readableEnded) {
          reqEnded = true
          done({ bodyComplete: true, transport: 'complete', aborted: false, budgetExceeded: false })
        } else {
          req.pause()
          reasons.push('>=64KiB')
          done({ bodyComplete: false, transport: 'truncated', aborted: false, budgetExceeded: false })
        }
        return
      }
      // Chunk straddles 64 KiB boundary: split cleanly into prefix + overflow
      const need = MAX_PREFIX_BYTES - prefixLen
      if (need > 0) {
        prefixChunks.push(chunk.subarray(0, need))
        prefixLen = MAX_PREFIX_BYTES
      }
      overflowChunks.push(chunk.subarray(need))
      req.pause()
      reasons.push('>64KiB')
      done({ bodyComplete: false, transport: 'truncated', aborted: false, budgetExceeded: false })
    }

    const timer = setTimeout(() => {
      req.pause()
      reasons.push('prefix-timeout')
      done({ bodyComplete: false, transport: 'truncated', aborted: false, budgetExceeded: false })
    }, prefixTimeoutMs)
    timer.unref?.()

    if (req.readableEnded) {
      reqEnded = true
      done({ bodyComplete: true, transport: 'complete', aborted: false, budgetExceeded: false })
      return
    }
    req.on('data', onData)
    req.on('end', onEnd)
    req.on('error', onError)
    res.on('close', onResClose)
  })
}

async function replayChunksAndPipe(
  req: http.IncomingMessage,
  up: http.ClientRequest,
  chunks: Buffer[],
  isEnded: () => boolean,
  onTailBytes: (n: number) => void,
) {
  for (const c of chunks) {
    if (up.destroyed) return
    if (!c.length) continue
    if (!up.write(c)) {
      await new Promise<void>(r => {
        const done = () => { up.off('drain', done); up.off('close', done); up.off('error', done); r() }
        up.once('drain', done)
        up.once('close', done)
        up.once('error', done)
      })
    }
  }
  if (up.destroyed) return
  if (isEnded() || req.readableEnded) {
    up.end()
  } else {
    req.on('data', (c: Buffer) => onTailBytes(c.length))
    req.pipe(up)
    req.resume()
  }
}

// One proxy per browser session, on a unix socket only that session's container can reach.
// CONNECT tunnels are opened locally (TLS ends here, with a key the browser is told to accept),
// so every request is seen whole: checked against the site's hosts, then logged.
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
  const v2Enabled = Boolean(opts?.auditV2 || opts?.policyHook)
  const projection: ProjectionMode = opts?.auditV2?.projection ?? 'semantic'
  const vault = opts?.vault
  const policyHook = opts?.policyHook
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
  const maxConcurrentAsyncHooks = opts?.maxConcurrentAsyncHooks ?? 8
  const isLiveNow = opts?.isLiveOrCooldown ?? isLive

  let seqCounter = 0
  let cursorCounter = 0
  let logBytes = 0
  let reservedBytes = 0
  let sampleBytes = 0
  let droppedGets = 0
  let refusedFullCount = 0
  let incompleteAtSeal = 0
  let activeAsyncHooks = 0
  let sealed = false
  const collapsedGets: Record<string, { count: number; bytes: number }> = {}
  const activeUpstreams = new Set<http.ClientRequest | net.Socket>()
  const activeInFlight = new Map<number, { finalize: () => void }>()
  const activeAbortControllers = new Set<AbortController>()

  const matches = (list: string[], host: string) => list.some(h => h.toLowerCase() === host || h.startsWith('*.') && host.endsWith(h.slice(1).toLowerCase()))
  // The site's hosts as they are now: a PUT adds those its person allows as the session goes (server.ts).
  const exact = (host: string) => site.hosts.some(h => h.toLowerCase() === host)
  // A trailing dot names the same host: through via, it is never resolved here.
  const via = (host: string) => !!site.via && matches(site.via.hosts, host.replace(/\.$/, ''))
  // The site's headers, such as a token its sign-in needs that its pages never send, go only to start_url's origin, added here, so
  // the browser, and anyone on its CDP, never holds them.
  const origin = site.start_url && new URL(site.start_url).origin
  const secureContext = tls.createSecureContext(key)
  // Separate pools: removing an exact host with PUT must not reuse its intranet connection for a public-only name.
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

  // Inside a tunnel, origin-form only; outside, absolute http(s) URLs only. Anything else is malformed.
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
    if (net.isIP(ip)) return !exact(host) ? 'host not on the list' : !via(host) && (site.public ? isInternal : isNever)(ip, net.isIP(ip)) ? 'internal address' : undefined
    if (!matches(site.hosts, host) && !site.open) return 'host not on the list'
  }

  const upstreamOptions = (req: http.IncomingMessage, url: URL) => {
    const headers = { ...req.headers, ...(url.origin === origin && site.headers), host: url.host }
    for (const h of hopByHop) delete headers[h]
    // Always strip Expect from upstream headers (§2.4.2)
    delete headers['expect']
    const strict = !!site.public || !exact(url.hostname)
    return { method: req.method, headers, lookup: lookup(strict), agent: agents[via(url.hostname) ? 2 : strict ? 1 : 0][url.protocol as 'http:'], servername: net.isIP(url.hostname) ? undefined : url.hostname }
  }

  // Reserve space for a write entry before dispatching (auditV2 only).
  const tryReserveWrite = (): number => {
    if (!v2Enabled) return 0
    const avail = Math.max(0, maxLogHardBytes - TAIL_RESERVE_BYTES - logBytes - reservedBytes)
    if (avail < MINIMAL_RESERVE_BYTES) return -1
    const want = logBytes < maxLogSoftBytes && avail >= MAX_ENTRY_BYTES ? MAX_ENTRY_BYTES : MINIMAL_RESERVE_BYTES
    reservedBytes += want
    return want
  }

  const releaseReservation = (amount: number) => {
    if (amount > 0) reservedBytes = Math.max(0, reservedBytes - amount)
  }

  const shouldCollapseGet = (entry: V2Entry): boolean => {
    if (!v2Enabled) return false
    if (entry.isWrite || entry.blocked || entry.error || entry.kind !== 'http') return false
    if (entry.status < 200 || entry.status >= 400) return false
    if (logBytes < collapseGetsAfterBytes && log.length < collapseGetsAfterEntries) return false
    return STATIC_DESTS.has(entry.dest ?? '') || entry.status === 304 || (logBytes >= maxLogSoftBytes && entry.dest !== 'document')
  }

  const appendV2Entry = (entryWithoutN: Omit<V2Entry, 'n'>): number | null => {
    if (sealed) return null
    const draft: V2Entry = { n: cursorCounter + 1, ...entryWithoutN }

    if (shouldCollapseGet(draft)) {
      const bucket = `${draft.authority || 'unknown'}:${draft.dest ?? 'other'}`
      const cur = collapsedGets[bucket] ?? { count: 0, bytes: 0 }
      cur.count++
      cur.bytes += draft.resBytes ?? 0
      collapsedGets[bucket] = cur
      return null
    }

    const normalLimit = Math.max(0, maxLogHardBytes - TAIL_RESERVE_BYTES)
    // Non-write GET above hard limit: drop GET (never drop write/blocked/error)
    if (!draft.isWrite && !draft.blocked && !draft.error && logBytes + MINIMAL_RESERVE_BYTES > normalLimit) {
      droppedGets++
      return null
    }

    let finalEntry: V2Entry
    let bytes: number
    if (logBytes >= maxLogSoftBytes) {
      finalEntry = toMinimalCappedEntry(draft)
      bytes = Buffer.byteLength(JSON.stringify(finalEntry))
    } else {
      const capped = capEntryTo12KiB(draft)
      if (logBytes + capped.bytes > normalLimit) {
        finalEntry = toMinimalCappedEntry(draft)
        bytes = Buffer.byteLength(JSON.stringify(finalEntry))
      } else {
        finalEntry = capped.entry
        bytes = capped.bytes
      }
    }

    if (finalEntry.reqBody) {
      sampleBytes += Buffer.byteLength(finalEntry.reqBody)
    }

    finalEntry.n = ++cursorCounter
    log.push(finalEntry)
    logBytes += bytes
    opts?.onEntry?.(finalEntry)
    return finalEntry.n
  }

  const appendLateOutcome = (rec: Omit<LateOutcomeEntry, 'n'>): void => {
    if (sealed || !v2Enabled) return
    const full: LateOutcomeEntry = { n: ++cursorCounter, ...rec }
    const bytes = Buffer.byteLength(JSON.stringify(full))
    if (logBytes + bytes > maxLogHardBytes) return
    log.push(full)
    logBytes += bytes
    opts?.onEntry?.(full)
  }

  const recordLegacy = (req: http.IncomingMessage, url: URL | null, status: number, extra: Partial<LegacyEntry> = {}) => {
    if (sealed) return
    const dest = req.headers['sec-fetch-dest'] as string | undefined
    const from = req.headers.referer
    const entry: LegacyEntry = {
      t: new Date().toISOString(),
      method: req.method!,
      url: url?.href ?? req.url!,
      status,
      ...(dest && { dest }),
      ...(from && { from }),
      ...extra,
      ...(isLiveNow() ? { live: true as const } : {}),
    }
    log.push(entry)
    logBytes += Buffer.byteLength(JSON.stringify(entry))
    opts?.onEntry?.(entry)
  }

  const buildSafeProjection = async (params: {
    req: http.IncomingMessage
    url: URL | null
    seq: number
    t: string
    kind: 'http' | 'upgrade'
    prefixBuf: Buffer
    bodyComplete: boolean
    transport: 'complete' | 'truncated' | 'not-read'
    transportReasons: string[]
    liveAtStart: boolean
    liveNow: boolean
    sem: ReturnType<typeof parseSemanticMethods>
    declaredBytes?: number
    hasBody: boolean
    httpCursorAtArrival: number
    cdpCursorAtArrival: number
  }): Promise<{ safe: SafeRequestProjection; raw?: RequestDescriptor['raw'] }> => {
    const { req, url, seq, t, kind, prefixBuf, bodyComplete, transport, transportReasons, liveAtStart, liveNow, sem, declaredBytes, hasBody } = params
    const sanUrl = url
      ? sanitizeUrl(url, { projection, vault })
      : sanitizeUrl(req.url ?? '/', { projection, vault })

    let vaultRedactions = sanUrl.vaultRedactions + sem.vaultRedactions
    const dest = typeof req.headers['sec-fetch-dest'] === 'string' ? req.headers['sec-fetch-dest'] : undefined
    let from: string | undefined
    if (typeof req.headers.referer === 'string' && req.headers.referer) {
      const sanFrom = sanitizeUrl(req.headers.referer, { projection, vault })
      from = sanFrom.url
      vaultRedactions += sanFrom.vaultRedactions
    }

    const reqType = normalizeContentType(req.headers['content-type'])
    const hasBodyOnSafe = SAFE_METHODS.has(sem.wireMethod) && (hasBody || prefixBuf.length > 0 || (declaredBytes ?? 0) > 0 || Boolean(req.headers['transfer-encoding']))
    const isWrite = !SAFE_METHODS.has(sem.wireMethod) || !SAFE_METHODS.has(sem.effectiveMethod) || sem.invalidOrConflictingOverride || hasBodyOnSafe
    const isAuth = url ? isAuthUrl(url) : false

    let decodeRes = undefined
    if (kind === 'http' && prefixBuf.length > 0 && !liveAtStart) {
      try {
        decodeRes = await decompressPrefix(prefixBuf, typeof req.headers['content-encoding'] === 'string' ? req.headers['content-encoding'] : undefined, bodyComplete)
      } catch {
        decodeRes = { ok: false, buf: Buffer.alloc(0), decodeComplete: false, decode: 'error' as const, truncated: false, reason: 'decompress-err' }
      }
    }

    const extracted = extractSemantic({
      url: url ?? new URL('http://invalid/'),
      sanitizedPath: sanUrl.path,
      method: sem.wireMethod,
      effectiveMethod: sem.effectiveMethod,
      kind,
      hdr: sem.hdr,
      rawHeaders: req.headers,
      reqType,
      decodedBuf: decodeRes ? decodeRes.buf : prefixBuf,
      decodeResult: decodeRes,
      bodyComplete,
      transport,
      transportReasons,
      isWrite,
      isAuth,
      isLive: liveAtStart || liveNow,
      projection,
      vault,
      sampleBudgetOk: sampleBytes < maxSampleBytes,
    })
    vaultRedactions += extracted.vaultRedactions

    // If GraphQL persisted or mutation/mixed, ensure isWrite reflects it? Note: GraphQL is usually POST anyway,
    // and GET GraphQL mutations are rejected by servers, though our isWrite already covers !SAFE.
    const siteConfigRev = opts?.getSiteConfigRev?.()
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
      method: sem.wireMethod,
      effectiveMethod: sem.effectiveMethod,
      methodSource: sem.methodSource,
      isWrite,
      ...(sem.hdr && { hdr: sem.hdr }),
      ...(sem.hdrConflict && { hdrConflict: true as const }),
      ...(dest && { dest }),
      ...(from && { from }),
      ...(reqType && { reqType }),
      ...(declaredBytes !== undefined && { declaredBytes }),
      prefixBytes: prefixBuf.length,
      bodyComplete,
      decodeComplete: extracted.decodeComplete,
      completeness: extracted.completeness,
      actions: extracted.actions,
      ...(extracted.bodyShape && { bodyShape: extracted.bodyShape }),
      ...(extracted.graphqlOp && { graphqlOp: extracted.graphqlOp }),
      ...(extracted.dupKeys && { dupKeys: true as const }),
      ...(vaultRedactions > 0 && { vaultRedactions }),
      cdpCursor: params.cdpCursorAtArrival,
      httpCursor: params.httpCursorAtArrival,
      ...(siteConfigRev !== undefined && { siteConfigRev }),
      ...(liveAtStart && { live: true as const }),
      ...(extracted.reqBody !== undefined && { reqBody: extracted.reqBody }),
      ...(extracted.reqTrunc && { reqTrunc: true as const }),
      ...(extracted.reqOmitted && { reqOmitted: extracted.reqOmitted }),
    }

    const raw: RequestDescriptor['raw'] | undefined = url
      ? {
          url: url.href,
          ...(extracted.parsedBody !== undefined && { parsedBody: extracted.parsedBody }),
          ...(extracted.rawBodyText !== undefined && { rawBodyText: extracted.rawBodyText }),
          ...(declaredBytes !== undefined && { declaredBytes }),
        }
      : undefined

    return { safe, raw }
  }

  const runPolicyHook = async (
    hook: PolicyHookConfig,
    descriptor: RequestDescriptor,
    abortSignal: AbortSignal,
    cdpCursorAtArrival: number,
    httpCursorAtArrival: number,
  ): Promise<{ decision: PolicyDecision; busy?: boolean }> => {
    const decisionId = crypto.randomUUID()
    const deadlineDuration = hook.deadlineMs ?? 20_000
    const deadlineMs = Date.now() + deadlineDuration
    const ctx: PolicyContext = {
      decisionId,
      signal: abortSignal,
      deadlineMs,
      intent: opts?.auditV2?.intent,
      recentCdpCursor: cdpCursorAtArrival,
      recentHttpCursor: httpCursorAtArrival,
    }
    const start = performance.now()
    const makeErrorDecision = (): PolicyDecision => ({
      decisionId,
      mode: hook.mode,
      stage: 1,
      action: 'deny',
      ruleId: 'policy_error',
      policyVersion: 'host-fallback',
      ms: Math.round(performance.now() - start),
    })

    let result: PolicyDecision | Promise<PolicyDecision>
    try {
      result = hook.evaluate(descriptor, ctx)
    } catch {
      return { decision: makeErrorDecision() }
    }

    // Synchronous return (e.g. fast Stage-1 GET check): never consumes async hook slot!
    if (!result || typeof (result as any).then !== 'function') {
      const dec = result as PolicyDecision
      if (!dec || typeof dec.action !== 'string' || !['allow', 'deny', 'escalate', 'requireApproval'].includes(dec.action)) {
        return { decision: makeErrorDecision() }
      }
      return { decision: { ...dec, decisionId: dec.decisionId || decisionId } }
    }

    if (hook.mode === 'enforce' && activeAsyncHooks >= maxConcurrentAsyncHooks) {
      return { decision: makeErrorDecision(), busy: true }
    }
    activeAsyncHooks++
    let timer: NodeJS.Timeout | undefined
    try {
      const settled = await Promise.race([
        result,
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error('policy timeout')), deadlineDuration)
          timer.unref?.()
        }),
      ])
      if (!settled || typeof settled.action !== 'string' || !['allow', 'deny', 'escalate', 'requireApproval'].includes(settled.action)) {
        return { decision: makeErrorDecision() }
      }
      return { decision: { ...settled, decisionId: settled.decisionId || decisionId } }
    } catch {
      return { decision: makeErrorDecision() }
    } finally {
      clearTimeout(timer)
      activeAsyncHooks = Math.max(0, activeAsyncHooks - 1)
    }
  }

  const forward = (req: http.IncomingMessage, res: http.ServerResponse) => {
    const startMs = performance.now()
    const t = new Date().toISOString()
    const url = urlOf(req)

    if (!v2Enabled) {
      const blocked = check(url)
      if (blocked) {
        recordLegacy(req, url, 403, { blocked })
        res.writeHead(403, { 'content-type': 'text/plain' }).end(`rollforward-browser: ${blocked}: ${req.method} ${url?.href ?? req.url}\n`)
        return
      }
      const liveAtStart = isLive(), genAtStart = liveGen?.()
      const up = (url!.protocol === 'https:' ? https : http).request(url!, upstreamOptions(req, url!), r => {
        recordLegacy(req, url, r.statusCode!)
        if (onWrite && !liveAtStart && !SAFE_METHODS.has(req.method!.toUpperCase())) {
          r.on('end', () => { if (!isLive() && liveGen?.() === genAtStart) onWrite() })
        }
        const headers = { ...r.headers }
        for (const h of hopByHop) delete headers[h]
        res.writeHead(r.statusCode!, headers)
        r.pipe(res)
      })
      activeUpstreams.add(up)
      up.on('close', () => activeUpstreams.delete(up))
      res.on('close', () => { if (!res.writableFinished) up.destroy() })
      up.on('error', e => {
        recordLegacy(req, url, 502, { error: e.message })
        if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' }).end(`rollforward-browser: ${e.message}\n`)
        else res.destroy()
      })
      req.pipe(up)
      return
    }

    // ---- auditV2 / policyHook path ----
    void handleV2Request(req, res, url, t, startMs).catch(() => {
      if (!res.headersSent && !res.destroyed) {
        res.writeHead(500, { 'content-type': 'text/plain' }).end('rollforward-browser: internal proxy error\n')
      }
    })
  }

  const handleV2Request = async (
    req: http.IncomingMessage,
    res: http.ServerResponse,
    url: URL | null,
    t: string,
    startMs: number,
  ) => {
    const seq = ++seqCounter
    const httpCursorAtArrival = cursorCounter
    const cdpCursorAtArrival = opts?.getCdpCursor?.() ?? 0
    const liveAtStart = isLiveNow()
    const genAtStart = liveGen?.()

    try {
      vault?.ingestRequestHeaders(req.headers)
    } catch {}

    const sem = parseSemanticMethods(req, vault)
    const declaredBytes = parseDeclaredBytes(req)
    const hasPotentialBody = !SAFE_METHODS.has(sem.wireMethod) || (declaredBytes ?? 0) > 0 || Boolean(req.headers['transfer-encoding'])
    const prelimWrite = !SAFE_METHODS.has(sem.wireMethod) || !SAFE_METHODS.has(sem.effectiveMethod) || sem.invalidOrConflictingOverride || hasPotentialBody

    const blocked = check(url)
    if (blocked) {
      const { safe } = await buildSafeProjection({
        req, url, seq, t, kind: 'http', prefixBuf: Buffer.alloc(0), bodyComplete: true,
        transport: 'not-read', transportReasons: [], liveAtStart, liveNow: isLiveNow(),
        sem, declaredBytes, hasBody: false, httpCursorAtArrival, cdpCursorAtArrival,
      })
      appendV2Entry({ ...safe, status: 403, blocked, dispatch: 'not_dispatched', ms: Math.round(performance.now() - startMs) })
      res.writeHead(403, { 'content-type': 'text/plain' }).end(`rollforward-browser: ${blocked}: ${req.method} ${url?.href ?? req.url}\n`)
      return
    }

    // Reserve hard log capacity before dispatching any write on auditV2 sessions
    let reserved = 0
    if (prelimWrite) {
      reserved = tryReserveWrite()
      if (reserved < 0) {
        refusedFullCount++
        res.writeHead(403, { 'content-type': 'application/json', connection: 'close' }).end(JSON.stringify({ error: 'audit log full' }))
        return
      }
    }

    const abortController = new AbortController()
    activeAbortControllers.add(abortController)
    const cleanupAbort = () => activeAbortControllers.delete(abortController)

    // Determine effective policy mode (liveMode override when live & non-auth)
    let activeHook: PolicyHookConfig | undefined = policyHook
    if (activeHook && liveAtStart) {
      const liveMode = activeHook.liveMode ?? 'enforce'
      if (liveMode === 'allow') activeHook = undefined
      else if (liveMode === 'shadow') activeHook = { ...activeHook, mode: 'shadow' }
    }

    // ENFORCE MODE: PrefixReader -> evaluate -> allow/deny before opening upstream!
    if (activeHook && activeHook.mode === 'enforce') {
      let prefixBuf = Buffer.alloc(0)
      let overflowChunks: Buffer[] = []
      let bodyComplete = true
      let transport: 'complete' | 'truncated' | 'not-read' = 'not-read'
      let transportReasons: string[] = []
      let totalReqBytes = 0
      let releasePrefixBudget = () => {}
      let onEndFlag = () => req.readableEnded

      if (hasPotentialBody) {
        const pr = await readBoundedPrefix(req, res, inFlightTracker, clientId, sessionId, prefixTimeoutMs, abortController)
        prefixBuf = pr.prefixBuf
        overflowChunks = pr.overflowChunks
        bodyComplete = pr.bodyComplete
        transport = pr.transport
        transportReasons = pr.reasons
        totalReqBytes = pr.totalReadBytes
        releasePrefixBudget = pr.releaseBudget
        onEndFlag = pr.onEndFlag

        if (pr.aborted) {
          releasePrefixBudget()
          releaseReservation(reserved)
          cleanupAbort()
          const { safe } = await buildSafeProjection({
            req, url, seq, t, kind: 'http', prefixBuf, bodyComplete: false,
            transport: 'truncated', transportReasons: [...transportReasons, 'client-abort'],
            liveAtStart, liveNow: isLiveNow(), sem, declaredBytes, hasBody: totalReqBytes > 0,
            httpCursorAtArrival, cdpCursorAtArrival,
          })
          appendV2Entry({ ...safe, status: 0, reqBytes: totalReqBytes, dispatch: 'not_dispatched', incomplete: true, ms: Math.round(performance.now() - startMs) })
          return
        }

        if (pr.budgetExceeded) {
          releasePrefixBudget()
          releaseReservation(reserved)
          cleanupAbort()
          const { safe } = await buildSafeProjection({
            req, url, seq, t, kind: 'http', prefixBuf, bodyComplete: false,
            transport: 'truncated', transportReasons: [...transportReasons, 'inflight-budget'],
            liveAtStart, liveNow: isLiveNow(), sem, declaredBytes, hasBody: totalReqBytes > 0,
            httpCursorAtArrival, cdpCursorAtArrival,
          })
          appendV2Entry({ ...safe, status: 503, blocked: 'capture budget exceeded', dispatch: 'not_dispatched', ms: Math.round(performance.now() - startMs) })
          res.writeHead(503, { 'content-type': 'application/json', connection: 'close' }).end(JSON.stringify({ error: 'capture budget exceeded' }))
          return
        }
      }

      const descriptor = await buildSafeProjection({
        req, url, seq, t, kind: 'http', prefixBuf, bodyComplete, transport, transportReasons,
        liveAtStart, liveNow: isLiveNow(), sem, declaredBytes, hasBody: totalReqBytes > 0,
        httpCursorAtArrival, cdpCursorAtArrival,
      })

      const hookRes = await runPolicyHook(activeHook, descriptor, abortController.signal, cdpCursorAtArrival, httpCursorAtArrival)

      if (hookRes.busy) {
        releasePrefixBudget()
        releaseReservation(reserved)
        cleanupAbort()
        appendV2Entry({ ...descriptor.safe, status: 503, blocked: 'policy busy', dispatch: 'not_dispatched', policy: hookRes.decision, ms: Math.round(performance.now() - startMs) })
        res.writeHead(503, { 'content-type': 'application/json', connection: 'close' }).end(JSON.stringify({ error: 'policy evaluator busy' }))
        return
      }

      if (abortController.signal.aborted || sealed) {
        releasePrefixBudget()
        releaseReservation(reserved)
        cleanupAbort()
        appendV2Entry({ ...descriptor.safe, status: 0, reqBytes: totalReqBytes, dispatch: 'not_dispatched', policy: hookRes.decision, incomplete: true, ms: Math.round(performance.now() - startMs) })
        return
      }

      if (hookRes.decision.action !== 'allow') {
        releasePrefixBudget()
        releaseReservation(reserved)
        cleanupAbort()
        const lateLive = !liveAtStart && (isLiveNow() || liveGen?.() !== genAtStart)
        appendV2Entry({
          ...descriptor.safe,
          status: 403,
          blocked: 'blocked by policy',
          dispatch: 'not_dispatched',
          policy: hookRes.decision,
          ...(lateLive && { liveAtEnd: true as const }),
          ms: Math.round(performance.now() - startMs),
        })
        const respHeaders: Record<string, string> = { 'content-type': 'application/json' }
        if (!bodyComplete) respHeaders.connection = 'close'
        res.writeHead(403, respHeaders).end(JSON.stringify({
          error: 'blocked by policy',
          ruleId: hookRes.decision.ruleId,
          decisionId: hookRes.decision.decisionId,
        }))
        return
      }

      // Recheck mutable authorization (PUT /hosts) after async wait before opening upstream!
      const recheckBlocked = check(url)
      if (recheckBlocked) {
        releasePrefixBudget()
        releaseReservation(reserved)
        cleanupAbort()
        appendV2Entry({
          ...descriptor.safe,
          status: 403,
          blocked: recheckBlocked,
          dispatch: 'not_dispatched',
          policy: hookRes.decision,
          ms: Math.round(performance.now() - startMs),
        })
        const respHeaders: Record<string, string> = { 'content-type': 'text/plain' }
        if (!bodyComplete) respHeaders.connection = 'close'
        res.writeHead(403, respHeaders).end(`rollforward-browser: ${recheckBlocked}: ${req.method} ${url?.href ?? req.url}\n`)
        return
      }

      // Admitted! Dispatch upstream and replay buffered chunks byte-for-byte.
      dispatchUpstream({
        req, res, url: url!, seq, startMs, liveAtStart, genAtStart, reserved,
        abortController, cleanupAbort,
        preBuiltSafe: descriptor.safe,
        policyDecision: hookRes.decision,
        replay: {
          chunks: [...(prefixBuf.length ? [prefixBuf] : []), ...overflowChunks],
          initialBytes: totalReqBytes,
          isEnded: onEndFlag,
          releaseBudget: releasePrefixBudget,
        },
      })
      return
    }

    // OBSERVE or SHADOW MODE: zero-latency forwarding with passive tee & identical 64 KiB / 10 s cutoff!
    const teeChunks: Buffer[] = []
    let teeLen = 0
    let teeAcquired = 0
    let teeFrozen = !hasPotentialBody
    let teeComplete = !hasPotentialBody
    let teeTransport: 'complete' | 'truncated' | 'not-read' = hasPotentialBody ? 'truncated' : 'not-read'
    const teeReasons: string[] = []
    let totalReqBytes = 0
    let budgetHit = false
    let prefixFrozenResolve: (() => void) | undefined
    const prefixFrozenPromise = new Promise<void>(r => { prefixFrozenResolve = r })

    const releaseTeeBudget = () => {
      if (teeAcquired > 0) {
        inFlightTracker.release(clientId, sessionId, teeAcquired)
        teeAcquired = 0
      }
    }

    let prefixTimer: NodeJS.Timeout | undefined
    const freezeTee = (complete: boolean, reason?: string) => {
      if (teeFrozen) return
      teeFrozen = true
      clearTimeout(prefixTimer)
      teeComplete = complete
      teeTransport = complete ? 'complete' : 'truncated'
      if (reason && !teeReasons.includes(reason)) teeReasons.push(reason)
      prefixFrozenResolve?.()
    }

    if (hasPotentialBody) {
      prefixTimer = setTimeout(() => freezeTee(false, 'prefix-timeout'), prefixTimeoutMs)
      prefixTimer.unref?.()
    } else {
      prefixFrozenResolve?.()
    }

    req.on('data', (chunk: Buffer) => {
      try {
        totalReqBytes += chunk.length
        // Safe wire verb unexpectedly carrying a body
        if (!hasPotentialBody && teeTransport === 'not-read') {
          teeFrozen = false
          teeComplete = false
          teeTransport = 'truncated'
        }
        if (teeFrozen) return
        if (teeLen >= MAX_PREFIX_BYTES) {
          freezeTee(false, '>64KiB')
          return
        }
        const take = Math.min(chunk.length, MAX_PREFIX_BYTES - teeLen)
        if (!inFlightTracker.tryAcquire(clientId, sessionId, take)) {
          budgetHit = true
          freezeTee(false, 'budget')
          return
        }
        teeAcquired += take
        teeChunks.push(chunk.subarray(0, take))
        teeLen += take
        if (chunk.length > take) {
          freezeTee(false, '>64KiB')
        }
      } catch {}
    })
    req.on('end', () => {
      if (!teeFrozen) freezeTee(true)
    })

    // Shadow hook runner (async after prefix freezes; zero added latency to upstream!)
    let shadowDecision: PolicyDecision | undefined
    let emittedEntryN: number | null = null
    const buildObserveDescriptor = async () => {
      const prefixBuf = Buffer.concat(teeChunks)
      releaseTeeBudget()
      const built = await buildSafeProjection({
        req, url, seq, t, kind: 'http', prefixBuf,
        bodyComplete: teeComplete,
        transport: teeTransport,
        transportReasons: teeReasons,
        liveAtStart, liveNow: isLiveNow(), sem, declaredBytes, hasBody: totalReqBytes > 0,
        httpCursorAtArrival, cdpCursorAtArrival,
      })
      if (budgetHit && !built.safe.reqOmitted && built.safe.isWrite) {
        built.safe.reqOmitted = 'budget'
      }
      return built
    }

    let builtPromise: Promise<{ safe: SafeRequestProjection; raw?: RequestDescriptor['raw'] }> | undefined
    const getBuilt = () => {
      if (!teeFrozen) freezeTee(req.readableEnded)
      return (builtPromise ??= buildObserveDescriptor())
    }

    if (activeHook && activeHook.mode === 'shadow') {
      void prefixFrozenPromise.then(async () => {
        if (sealed) return
        const desc = await getBuilt()
        const hr = await runPolicyHook(activeHook!, desc, abortController.signal, cdpCursorAtArrival, httpCursorAtArrival)
        shadowDecision = hr.decision
        if (emittedEntryN !== null && !sealed) {
          appendLateOutcome({
            rec: 'http_end',
            ref: emittedEntryN,
            t: new Date().toISOString(),
            ms: Math.round(performance.now() - startMs),
            policy: shadowDecision,
          })
        }
      }).catch(() => {})
    }

    dispatchUpstream({
      req, res, url: url!, seq, startMs, liveAtStart, genAtStart, reserved,
      abortController, cleanupAbort,
      getLazySafe: async () => (await getBuilt()).safe,
      getShadowDecision: () => shadowDecision,
      onEmittedN: n => { emittedEntryN = n },
      getReqBytes: () => totalReqBytes,
      onCleanupTee: () => {
        clearTimeout(prefixTimer)
        releaseTeeBudget()
      },
    })
  }

  const dispatchUpstream = (ctx: {
    req: http.IncomingMessage
    res: http.ServerResponse
    url: URL
    seq: number
    startMs: number
    liveAtStart: boolean
    genAtStart: number | undefined
    reserved: number
    abortController: AbortController
    cleanupAbort: () => void
    preBuiltSafe?: SafeRequestProjection
    policyDecision?: PolicyDecision
    getLazySafe?: () => Promise<SafeRequestProjection>
    getShadowDecision?: () => PolicyDecision | undefined
    onEmittedN?: (n: number | null) => void
    getReqBytes?: () => number
    onCleanupTee?: () => void
    replay?: {
      chunks: Buffer[]
      initialBytes: number
      isEnded: () => boolean
      releaseBudget: () => void
    }
  }) => {
    const { req, res, url, seq, startMs, liveAtStart, genAtStart, reserved, abortController, cleanupAbort } = ctx
    let resBytes = 0
    let replayTailBytes = 0
    let status = 0
    let resType: string | undefined
    let headerMs: number | undefined
    let errorMsg: string | undefined
    let emitted = false
    let emittedN: number | null = null
    let timedOutStream = false
    let finished = false
    let lateEmitted = false
    let upCreated = false

    const totalReqBytes = () => ctx.replay ? ctx.replay.initialBytes + replayTailBytes : (ctx.getReqBytes?.() ?? 0)

    const emitOnce = (optsEmit: { incomplete?: true; syncSeal?: boolean }) => {
      if (emitted) return
      emitted = true
      clearTimeout(streamTimer)
      activeInFlight.delete(seq)
      releaseReservation(reserved)
      ctx.onCleanupTee?.()
      ctx.replay?.releaseBudget()
      const ms = Math.round(performance.now() - startMs)
      const lateLive = !liveAtStart && (isLiveNow() || liveGen?.() !== genAtStart)
      const scrubbedErr = errorMsg ? scrubText(errorMsg, vault).text : undefined
      const decision = ctx.policyDecision ?? ctx.getShadowDecision?.()

      const commit = (safe: SafeRequestProjection) => {
        if (sealed && !optsEmit.syncSeal) return
        const n = appendV2Entry({
          ...safe,
          status,
          ...(scrubbedErr && { error: scrubbedErr }),
          ...(resType && { resType }),
          reqBytes: totalReqBytes(),
          resBytes,
          ...(headerMs !== undefined && { headerMs }),
          ms,
          dispatch: upCreated ? (optsEmit.syncSeal ? 'unknown' : 'dispatched') : 'not_dispatched',
          ...(decision && { policy: decision }),
          ...(lateLive && { liveAtEnd: true as const }),
          ...(optsEmit.incomplete && { incomplete: true as const }),
        })
        emittedN = n
        ctx.onEmittedN?.(n)
      }

      if (ctx.preBuiltSafe) {
        commit(ctx.preBuiltSafe)
      } else if (optsEmit.syncSeal) {
        // Synchronous seal fallback when async projection hasn't completed
        const sanUrl = sanitizeUrl(url, { projection, vault })
        const sem = parseSemanticMethods(req, vault)
        commit({
          descV: DESC_V, redactV: REDACT_V, extractorV: EXTRACTOR_V,
          surface: 'browser', target: { site: siteName }, seq, t: new Date().toISOString(),
          kind: 'http', scheme: sanUrl.scheme, authority: sanUrl.authority, path: sanUrl.path, url: sanUrl.url,
          method: sem.wireMethod, effectiveMethod: sem.effectiveMethod, methodSource: sem.methodSource,
          isWrite: !SAFE_METHODS.has(sem.wireMethod) || !SAFE_METHODS.has(sem.effectiveMethod),
          prefixBytes: 0, bodyComplete: false, decodeComplete: false,
          completeness: { transport: 'truncated', decode: 'none', extract: 'none', reasons: ['sealed-in-flight'] },
          actions: [],
          ...(liveAtStart && { live: true as const }),
        })
      } else if (ctx.getLazySafe) {
        void ctx.getLazySafe().then(commit).catch(() => {})
      }
    }

    const emitLateIfNeeded = (incomplete?: true) => {
      if (!timedOutStream || !emitted || lateEmitted || emittedN === null || sealed) return
      lateEmitted = true
      const scrubbedErr = errorMsg ? scrubText(errorMsg, vault).text : undefined
      appendLateOutcome({
        rec: 'http_end',
        ref: emittedN,
        t: new Date().toISOString(),
        reqBytes: totalReqBytes(),
        resBytes,
        ms: Math.round(performance.now() - startMs),
        ...(scrubbedErr && { error: scrubbedErr }),
        ...(incomplete && { incomplete: true as const }),
      })
    }

    const streamTimer = setTimeout(() => {
      if (!emitted && !finished) {
        timedOutStream = true
        emitOnce({ incomplete: true })
      }
    }, streamTimeoutMs)
    streamTimer.unref?.()

    activeInFlight.set(seq, {
      finalize: () => {
        if (!emitted) {
          incompleteAtSeal++
          emitOnce({ incomplete: true, syncSeal: true })
        }
      },
    })

    const up = (url.protocol === 'https:' ? https : http).request(url, upstreamOptions(req, url), r => {
      headerMs = Math.round(performance.now() - startMs)
      status = r.statusCode ?? 0
      resType = normalizeContentType(r.headers['content-type'])
      try {
        vault?.ingestSetCookie(r.headers['set-cookie'])
      } catch {}

      const headers = { ...r.headers }
      for (const h of hopByHop) delete headers[h]
      if (!res.destroyed) {
        res.writeHead(status, headers)
        r.pipe(res)
      }

      r.on('data', (c: Buffer) => { resBytes += c.length })
      r.on('end', () => {
        finished = true
        cleanupAbort()
        if (!emitted) {
          emitOnce({})
        } else {
          emitLateIfNeeded()
        }
        const dest = typeof req.headers['sec-fetch-dest'] === 'string' ? req.headers['sec-fetch-dest'] : undefined
        const sem = parseSemanticMethods(req)
        const isWriteReq = !SAFE_METHODS.has(sem.wireMethod) || !SAFE_METHODS.has(sem.effectiveMethod) || sem.invalidOrConflictingOverride
        if (!liveAtStart && isWriteReq && !isLiveNow() && liveGen?.() === genAtStart) {
          opts?.onWriteDetail?.({ dest, isWrite: true })
          if (!opts?.onWriteDetail) onWrite?.()
        }
      })
      r.on('aborted', () => {
        finished = true
        cleanupAbort()
        errorMsg ||= 'upstream response aborted'
        if (!emitted) emitOnce({ incomplete: true })
        else emitLateIfNeeded(true)
      })
      r.on('error', e => {
        finished = true
        cleanupAbort()
        errorMsg ||= e.message
        if (!emitted) emitOnce({ incomplete: true })
        else emitLateIfNeeded(true)
        if (!res.destroyed) res.destroy()
      })
    })
    upCreated = true
    activeUpstreams.add(up)
    up.on('close', () => activeUpstreams.delete(up))

    // Observe all 4 stream error/abort paths (§2.3.1)
    req.on('error', e => {
      finished = true
      abortController.abort()
      cleanupAbort()
      errorMsg ||= `client request error: ${e.message}`
      up.destroy()
      if (!emitted) emitOnce({ incomplete: true })
      else emitLateIfNeeded(true)
    })

    res.on('close', () => {
      if (!res.writableFinished) {
        finished = true
        abortController.abort()
        cleanupAbort()
        up.destroy()
        if (!emitted) emitOnce({ incomplete: true })
        else emitLateIfNeeded(true)
      }
    })

    up.on('error', e => {
      finished = true
      cleanupAbort()
      errorMsg ||= e.message
      if (status === 0) status = 502
      if (!emitted) emitOnce({})
      else emitLateIfNeeded(true)
      if (!res.headersSent && !res.destroyed) {
        res.writeHead(502, { 'content-type': 'text/plain' }).end(`rollforward-browser: ${e.message}\n`)
      } else if (!res.destroyed) {
        res.destroy()
      }
    })

    if (ctx.replay) {
      void replayChunksAndPipe(req, up, ctx.replay.chunks, ctx.replay.isEnded, n => { replayTailBytes += n }).catch(() => {
        up.destroy()
      })
    } else {
      req.pipe(up)
    }
  }

  const forwardUpgrade = (req: http.IncomingMessage, socket: net.Socket, head: Buffer) => {
    socket.on('error', () => socket.destroy())
    const startMs = performance.now()
    const t = new Date().toISOString()
    const url = urlOf(req)

    if (!v2Enabled) {
      const blocked = check(url)
      if (blocked) {
        recordLegacy(req, url, 403, { blocked })
        socket.end('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n')
        return
      }
      const uOpts = upstreamOptions(req, url!)
      uOpts.headers.connection = 'upgrade'
      uOpts.headers.upgrade = req.headers.upgrade
      const up = (url!.protocol === 'https:' ? https : http).request(url!, uOpts)
      activeUpstreams.add(up)
      up.on('close', () => activeUpstreams.delete(up))
      up.on('upgrade', (r, upSocket, upHead) => {
        activeUpstreams.add(upSocket)
        upSocket.on('close', () => activeUpstreams.delete(upSocket))
        upSocket.on('error', () => socket.destroy())
        socket.on('close', () => upSocket.destroy())
        recordLegacy(req, url, 101)
        socket.write(`HTTP/1.1 101 Switching Protocols\r\n${Object.entries(r.headers).map(([k, v]) => `${k}: ${v}\r\n`).join('')}\r\n`)
        upSocket.write(head)
        socket.write(upHead)
        upSocket.pipe(socket).pipe(upSocket)
      })
      up.on('response', r => {
        recordLegacy(req, url, r.statusCode!)
        socket.end(`HTTP/1.1 ${r.statusCode} ${r.statusMessage}\r\nconnection: close\r\n\r\n`)
      })
      up.on('error', e => {
        recordLegacy(req, url, 502, { error: e.message })
        socket.end('HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n')
      })
      up.end()
      return
    }

    // auditV2 / policyHook upgrade path
    void (async () => {
      const seq = ++seqCounter
      const httpCursorAtArrival = cursorCounter
      const cdpCursorAtArrival = opts?.getCdpCursor?.() ?? 0
      const liveAtStart = isLiveNow()
      try { vault?.ingestRequestHeaders(req.headers) } catch {}
      const sem = parseSemanticMethods(req, vault)
      const blocked = check(url)
      const descriptor = await buildSafeProjection({
        req, url, seq, t, kind: 'upgrade', prefixBuf: Buffer.alloc(0), bodyComplete: true,
        transport: 'not-read', transportReasons: [], liveAtStart, liveNow: isLiveNow(),
        sem, declaredBytes: undefined, hasBody: false, httpCursorAtArrival, cdpCursorAtArrival,
      })
      if (blocked) {
        appendV2Entry({ ...descriptor.safe, status: 403, blocked, dispatch: 'not_dispatched', ms: Math.round(performance.now() - startMs) })
        socket.end('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n')
        return
      }

      const abortController = new AbortController()
      activeAbortControllers.add(abortController)
      socket.once('close', () => abortController.abort())

      let policyDecision: PolicyDecision | undefined
      if (policyHook) {
        if (policyHook.mode === 'enforce') {
          const hr = await runPolicyHook(policyHook, descriptor, abortController.signal, cdpCursorAtArrival, httpCursorAtArrival)
          activeAbortControllers.delete(abortController)
          policyDecision = hr.decision
          if (hr.busy) {
            appendV2Entry({ ...descriptor.safe, status: 503, blocked: 'policy busy', dispatch: 'not_dispatched', policy: policyDecision, ms: Math.round(performance.now() - startMs) })
            socket.end('HTTP/1.1 503 Service Unavailable\r\nconnection: close\r\n\r\n')
            return
          }
          if (policyDecision.action !== 'allow' || socket.destroyed || sealed) {
            appendV2Entry({ ...descriptor.safe, status: 403, blocked: 'blocked by policy', dispatch: 'not_dispatched', policy: policyDecision, ms: Math.round(performance.now() - startMs) })
            socket.end('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n')
            return
          }
          const recheck = check(url)
          if (recheck) {
            appendV2Entry({ ...descriptor.safe, status: 403, blocked: recheck, dispatch: 'not_dispatched', policy: policyDecision, ms: Math.round(performance.now() - startMs) })
            socket.end('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n')
            return
          }
        } else {
          // shadow mode: run async
          void runPolicyHook(policyHook, descriptor, abortController.signal, cdpCursorAtArrival, httpCursorAtArrival).then(hr => {
            policyDecision = hr.decision
            activeAbortControllers.delete(abortController)
          }).catch(() => activeAbortControllers.delete(abortController))
        }
      } else {
        activeAbortControllers.delete(abortController)
      }

      const uOpts = upstreamOptions(req, url!)
      uOpts.headers.connection = 'upgrade'
      uOpts.headers.upgrade = req.headers.upgrade
      const up = (url!.protocol === 'https:' ? https : http).request(url!, uOpts)
      activeUpstreams.add(up)
      up.on('close', () => activeUpstreams.delete(up))
      up.on('upgrade', (r, upSocket, upHead) => {
        activeUpstreams.add(upSocket)
        upSocket.on('close', () => activeUpstreams.delete(upSocket))
        upSocket.on('error', () => socket.destroy())
        socket.on('close', () => upSocket.destroy())
        try { vault?.ingestSetCookie(r.headers['set-cookie']) } catch {}
        appendV2Entry({ ...descriptor.safe, status: 101, dispatch: 'dispatched', ...(policyDecision && { policy: policyDecision }), ms: Math.round(performance.now() - startMs) })
        socket.write(`HTTP/1.1 101 Switching Protocols\r\n${Object.entries(r.headers).map(([k, v]) => `${k}: ${v}\r\n`).join('')}\r\n`)
        upSocket.write(head)
        socket.write(upHead)
        upSocket.pipe(socket).pipe(upSocket)
      })
      up.on('response', r => {
        appendV2Entry({ ...descriptor.safe, status: r.statusCode ?? 0, dispatch: 'dispatched', ...(policyDecision && { policy: policyDecision }), ms: Math.round(performance.now() - startMs) })
        socket.end(`HTTP/1.1 ${r.statusCode} ${r.statusMessage}\r\nconnection: close\r\n\r\n`)
      })
      up.on('error', e => {
        const err = scrubText(e.message, vault).text
        appendV2Entry({ ...descriptor.safe, status: 502, error: err, dispatch: 'dispatched', ...(policyDecision && { policy: policyDecision }), ms: Math.round(performance.now() - startMs) })
        socket.end('HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n')
      })
      up.end()
    })().catch(() => socket.destroy())
  }

  // Explicit Expect handling on BOTH inner and outer HTTP servers (§2.4.2)
  const handleContinue = (req: http.IncomingMessage, res: http.ServerResponse) => {
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
    if (!v2Enabled) {
      recordLegacy(req, url, 417, { blocked: 'expectation failed' })
    } else {
      const seq = ++seqCounter
      const sem = parseSemanticMethods(req, vault)
      const sanUrl = url ? sanitizeUrl(url, { projection, vault }) : sanitizeUrl(req.url ?? '/', { projection, vault })
      appendV2Entry({
        descV: DESC_V, redactV: REDACT_V, extractorV: EXTRACTOR_V,
        surface: 'browser', target: { site: siteName }, seq, t: new Date().toISOString(),
        kind: 'http', scheme: sanUrl.scheme, authority: sanUrl.authority, path: sanUrl.path, url: sanUrl.url,
        method: sem.wireMethod, effectiveMethod: sem.effectiveMethod, methodSource: sem.methodSource,
        isWrite: !SAFE_METHODS.has(sem.wireMethod) || !SAFE_METHODS.has(sem.effectiveMethod),
        prefixBytes: 0, bodyComplete: false, decodeComplete: false,
        completeness: { transport: 'not-read', decode: 'none', extract: 'none', reasons: ['expectation-failed'] },
        actions: [], status: 417, blocked: 'expectation failed', dispatch: 'not_dispatched',
      })
    }
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
  outer.on('close', () => {
    inner.close()
    inner.closeAllConnections?.()
    agents.forEach(pool => Object.values(pool).forEach(a => a.destroy()))
  })

  outer.controller = {
    finalizeAtSeal: () => {
      if (sealed) return { logCursor: cursorCounter, droppedGets, refusedFull: refusedFullCount }
      for (const ac of activeAbortControllers) ac.abort()
      activeAbortControllers.clear()
      for (const up of activeUpstreams) up.destroy()
      activeUpstreams.clear()
      for (const item of [...activeInFlight.values()]) item.finalize()
      activeInFlight.clear()
      if (v2Enabled) {
        const summary: SummaryEntry = {
          n: ++cursorCounter,
          rec: '_summary',
          t: new Date().toISOString(),
          collapsedGets: { ...collapsedGets },
          droppedGets,
          refusedFullCount,
          incompleteAtSeal,
        }
        log.push(summary)
        logBytes += Buffer.byteLength(JSON.stringify(summary))
      }
      sealed = true
      return { logCursor: cursorCounter, droppedGets, refusedFull: refusedFullCount }
    },
    getLogPage: (after: number, limit = 500) => {
      const cappedLimit = Math.min(500, Math.max(1, limit))
      const v2Entries = log.filter((e): e is V2Entry | LateOutcomeEntry | SummaryEntry => typeof (e as any).n === 'number')
      const oldestCursor = v2Entries.length ? v2Entries[0].n : cursorCounter
      const out: LogRecord[] = []
      let pageBytes = 2
      let lastIdx = -1
      for (let i = 0; i < v2Entries.length; i++) {
        const e = v2Entries[i]
        if (e.n <= after) continue
        const size = Buffer.byteLength(JSON.stringify(e)) + 1
        if (out.length > 0 && (out.length >= cappedLimit || pageBytes + size > MAX_PAGE_BYTES)) break
        out.push(e)
        pageBytes += size
        lastIdx = i
      }
      const hasMore = lastIdx >= 0 && lastIdx < v2Entries.length - 1
      const nextCursor = out.length > 0 ? (out[out.length - 1] as any).n : Math.max(after, oldestCursor)
      return { oldestCursor, nextCursor, hasMore, dropped: droppedGets, entries: out }
    },
    getCurrentCursor: () => cursorCounter,
    getRetainedBytes: () => logBytes,
    clear: () => {
      log.length = 0
      logBytes = 0
      reservedBytes = 0
      sampleBytes = 0
    },
  }

  outer.listen(path)
  return outer
}
