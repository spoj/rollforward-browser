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
  truncateUtf8HeadTail,
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
  droppedLateOutcomes?: number
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
  // Optional fast synchronous Stage-1 pre-check (never consumes async hook capacity).
  // Return undefined to fall through to evaluate().
  checkSync?: (d: RequestDescriptor, ctx: PolicyContext) => PolicyDecision | undefined
  // Set true ONLY when evaluate() is guaranteed synchronous (non-Promise); returning a Promise fails closed.
  sync?: true
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

type SemanticMethodInfo = {
  wireMethod: string
  effectiveMethod: string
  methodSource: SafeRequestProjection['methodSource']
  hdr?: Record<string, string>
  hdrConflict: boolean
  invalidOrConflictingOverride: boolean
  vaultRedactions: number
}

function parseSemanticMethods(
  method: string | undefined,
  headers: Record<string, string | string[] | undefined>,
  vault?: SecretVault,
): SemanticMethodInfo {
  const wireMethod = (method ?? 'GET').toUpperCase()
  const hdr: Record<string, string> = {}
  let vaultRedactions = 0
  let invalid = false
  const validTokens: Array<{ header: typeof OVERRIDE_HEADERS[number]; verb: string }> = []

  for (const name of OVERRIDE_HEADERS) {
    const rawVal = headers[name]
    if (rawVal === undefined) continue
    const joined = Array.isArray(rawVal) ? rawVal.join(',') : rawVal
    const scrubbed = scrubText(truncateUtf8HeadTail(joined, 256), vault)
    vaultRedactions += scrubbed.vaultRedactions
    hdr[name] = scrubbed.text

    // Validate EVERY comma-separated member without silently dropping empty ones!
    const parts = joined.split(',').map(p => p.trim().toUpperCase())
    if (!parts.length) {
      invalid = true
      continue
    }
    for (const p of parts) {
      if (!p || !VALID_VERB_RE.test(p)) invalid = true
      else validTokens.push({ header: name, verb: p })
    }
  }

  const soapRaw = headers['soapaction']
  if (soapRaw !== undefined) {
    const joined = Array.isArray(soapRaw) ? soapRaw.join(',') : soapRaw
    const scrubbed = scrubText(truncateUtf8HeadTail(joined, 256), vault)
    vaultRedactions += scrubbed.vaultRedactions
    hdr.soapaction = scrubbed.text
  }

  const distinctVerbs = [...new Set(validTokens.map(v => v.verb))]
  const hdrConflict = distinctVerbs.length > 1
  const invalidOrConflictingOverride = invalid || hdrConflict

  let effectiveMethod = wireMethod
  let methodSource: SafeRequestProjection['methodSource'] = 'wire'

  if (validTokens.length > 0) {
    const unsafe = validTokens.find(v => !SAFE_METHODS.has(v.verb))
    if (unsafe) {
      effectiveMethod = unsafe.verb
      methodSource = unsafe.header
    } else if (SAFE_METHODS.has(wireMethod)) {
      effectiveMethod = validTokens[0].verb
      methodSource = validTokens[0].header
    } else {
      // Never downgrade write -> read
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

function parseDeclaredBytes(headers: Record<string, string | string[] | undefined>): number | undefined {
  const cl = headers['content-length']
  if (typeof cl !== 'string') return undefined
  const n = Number(cl.trim())
  return Number.isInteger(n) && n >= 0 ? n : undefined
}

function selectActiveHook(policyHook: PolicyHookConfig | undefined, liveAtStart: boolean): PolicyHookConfig | undefined {
  if (!policyHook) return undefined
  if (!liveAtStart) return policyHook
  const liveMode = policyHook.liveMode ?? 'enforce'
  if (liveMode === 'allow') return undefined
  if (liveMode === 'shadow') return { ...policyHook, mode: 'shadow' }
  return policyHook
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

function readBoundedPrefix(
  req: http.IncomingMessage,
  tracker: InFlightBudgetTracker,
  clientId: string,
  sessionId: string,
  prefixTimeoutMs: number,
  abortSignal: AbortSignal,
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
      abortSignal.removeEventListener('abort', onAbort)
    }

    const done = (resObj: Omit<PrefixReadResult, 'prefixBuf' | 'overflowChunks' | 'reasons' | 'totalReadBytes' | 'releaseBudget' | 'onEndFlag'>) => {
      if (settled) return
      settled = true
      cleanup()
      const prefixBuf = prefixChunks.length === 1 ? prefixChunks[0] : Buffer.concat(prefixChunks)
      prefixChunks.length = 0
      resolve({
        prefixBuf,
        overflowChunks,
        reasons,
        totalReadBytes,
        releaseBudget,
        onEndFlag: () => reqEnded || req.readableEnded,
        ...resObj,
      })
    }

    const markEnded = () => { reqEnded = true }
    req.once('end', markEnded)

    const onAbort = () => {
      req.pause()
      done({ bodyComplete: false, transport: 'truncated', aborted: true, budgetExceeded: false })
    }
    const onError = () => {
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
        prefixChunks.push(Buffer.from(chunk))
        prefixLen += chunk.length
        return
      }
      if (prefixLen + chunk.length === MAX_PREFIX_BYTES) {
        prefixChunks.push(Buffer.from(chunk))
        prefixLen = MAX_PREFIX_BYTES
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
      // Straddles 64 KiB boundary: copy slices so no giant slab is retained
      const need = MAX_PREFIX_BYTES - prefixLen
      if (need > 0) {
        prefixChunks.push(Buffer.from(chunk.subarray(0, need)))
        prefixLen = MAX_PREFIX_BYTES
      }
      overflowChunks.push(Buffer.from(chunk.subarray(need)))
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

    if (abortSignal.aborted) {
      onAbort()
      return
    }
    if (req.readableEnded) {
      reqEnded = true
      done({ bodyComplete: true, transport: 'complete', aborted: false, budgetExceeded: false })
      return
    }
    req.on('data', onData)
    req.on('end', onEnd)
    req.on('error', onError)
    abortSignal.addEventListener('abort', onAbort, { once: true })
  })
}

async function replayChunksAndPipe(
  req: http.IncomingMessage,
  up: http.ClientRequest,
  chunks: Buffer[],
  isEnded: () => boolean,
  onTailBytes: (n: number) => void,
  onUploadEnd: () => void,
  onChunksDrained: () => void,
) {
  for (let i = 0; i < chunks.length; i++) {
    const c = chunks[i]
    chunks[i] = Buffer.alloc(0) // drop reference promptly
    if (up.destroyed) {
      onChunksDrained()
      return
    }
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
  onChunksDrained()
  if (up.destroyed) return
  if (isEnded() || req.readableEnded) {
    up.end()
    onUploadEnd()
  } else {
    req.on('data', (c: Buffer) => onTailBytes(c.length))
    req.once('end', onUploadEnd)
    req.pipe(up)
    req.resume()
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
  let tailLogBytes = 0
  let reservedBytes = 0
  let sampleBytes = 0
  let droppedGets = 0
  let refusedFullCount = 0
  let incompleteAtSeal = 0
  let droppedLateOutcomes = 0
  let activeAsyncHooks = 0
  let admissionStopped = false
  let sealed = false
  const collapsedGets: Record<string, { count: number; bytes: number }> = {}
  const activeUpstreams = new Set<http.ClientRequest | net.Socket>()
  const activeTunnels = new Set<net.Socket>()
  const activeUpgradeSockets = new Set<net.Socket>()
  const activeInFlight = new Map<number, { finalize: () => void }>()
  const activeAbortControllers = new Set<AbortController>()

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
    const sem = parseSemanticMethods(req.method, hdrs, vault)
    const declaredBytes = parseDeclaredBytes(hdrs)
    // Check inbound req.headers['transfer-encoding'] too because buildOutboundSnapshot strips hop-by-hop headers!
    const hasBodyHint = (declaredBytes ?? 0) > 0 || Boolean(req.headers['transfer-encoding']) || Boolean(hdrs['transfer-encoding'])
    const hasPotentialBody = !SAFE_METHODS.has(sem.wireMethod) || hasBodyHint
    const isWrite = !SAFE_METHODS.has(sem.wireMethod) || !SAFE_METHODS.has(sem.effectiveMethod) || sem.invalidOrConflictingOverride || (SAFE_METHODS.has(sem.wireMethod) && hasBodyHint)
    const isAuth = url ? isAuthUrl(url) : false
    return { sem, declaredBytes, hasPotentialBody, isWrite, isAuth }
  }

  const sanitizeDestHeader = (headers: Record<string, string | string[] | undefined>): { dest?: string; vaultRedactions: number } => {
    const raw = headers['sec-fetch-dest']
    if (typeof raw !== 'string' || !raw) return { vaultRedactions: 0 }
    const lower = raw.trim().toLowerCase()
    if (ALLOWED_FETCH_DESTS.has(lower)) return { dest: lower, vaultRedactions: 0 }
    const s = scrubText(truncateUtf8HeadTail(raw, 32), vault)
    return { dest: s.vaultRedactions > 0 ? '[REDACTED:vault]' : 'other', vaultRedactions: s.vaultRedactions }
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
    if (!v2Enabled) return 0
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
    if (!v2Enabled) return false
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
    log.push(finalEntry)
    logBytes += bytes
    opts?.onEntry?.(finalEntry)
    return finalEntry.n
  }

  const appendLateOutcome = (rec: Omit<LateOutcomeEntry, 'n'>): void => {
    if (sealed || !v2Enabled) return
    const preview: LateOutcomeEntry = { n: cursorCounter + 1, ...rec }
    const bytes = Buffer.byteLength(JSON.stringify(preview), 'utf8')
    // Late outcomes draw strictly from TAIL_RESERVE_BYTES (leaving 8 KiB for _summary) so they can NEVER displace reserved normal writes!
    const summaryFloor = Math.min(8192, Math.floor(TAIL_RESERVE_BYTES / 2))
    if (tailLogBytes + bytes > TAIL_RESERVE_BYTES - summaryFloor) {
      droppedLateOutcomes++
      return
    }
    const full: LateOutcomeEntry = { n: ++cursorCounter, ...rec }
    log.push(full)
    tailLogBytes += bytes
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
    logBytes += Buffer.byteLength(JSON.stringify(entry), 'utf8')
    opts?.onEntry?.(entry)
  }

  const buildFallbackProjection = (params: {
    req: http.IncomingMessage
    url: URL | null
    seq: number
    t: string
    kind: 'http' | 'upgrade'
    arrival: ReturnType<typeof classifyArrival>
    liveAtStart: boolean
    httpCursorAtArrival: number
    cdpCursorAtArrival: number
    siteConfigRev?: number
    reason: string
  }): SafeRequestProjection => {
    const sanUrl = params.url ? sanitizeUrl(params.url, { projection, vault }) : sanitizeUrl(params.req.url ?? '/', { projection, vault })
    const destInfo = sanitizeDestHeader(params.req.headers)
    const dest = destInfo.dest
    return {
      descV: DESC_V,
      redactV: REDACT_V,
      extractorV: EXTRACTOR_V,
      surface: 'browser',
      target: { site: siteName },
      seq: params.seq,
      t: params.t,
      kind: params.kind,
      scheme: sanUrl.scheme,
      authority: sanUrl.authority,
      path: sanUrl.path,
      url: sanUrl.url,
      method: params.arrival.sem.wireMethod,
      effectiveMethod: params.arrival.sem.effectiveMethod,
      methodSource: params.arrival.sem.methodSource,
      isWrite: params.arrival.isWrite,
      ...(params.arrival.sem.hdr && { hdr: params.arrival.sem.hdr }),
      ...(params.arrival.sem.hdrConflict && { hdrConflict: true as const }),
      ...(dest && { dest }),
      ...(params.arrival.declaredBytes !== undefined && { declaredBytes: params.arrival.declaredBytes }),
      prefixBytes: 0,
      bodyComplete: false,
      decodeComplete: false,
      completeness: { transport: 'not-read', decode: 'none', extract: 'none', reasons: [params.reason] },
      actions: params.kind === 'upgrade' ? [{ family: 'upgrade', op: 'upgrade:websocket', resource: sanUrl.path, coverage: 'complete' }] : [],
      cdpCursor: params.cdpCursorAtArrival,
      httpCursor: params.httpCursorAtArrival,
      ...(params.siteConfigRev !== undefined && { siteConfigRev: params.siteConfigRev }),
      ...(params.liveAtStart && { live: true as const }),
    }
  }

  const buildSafeProjection = async (params: {
    req: http.IncomingMessage
    effectiveHeaders?: Record<string, string | string[] | undefined>
    url: URL | null
    seq: number
    t: string
    kind: 'http' | 'upgrade'
    prefixBuf: Buffer
    bodyComplete: boolean
    transport: 'complete' | 'truncated' | 'not-read'
    transportReasons: string[]
    liveAtStart: boolean
    genAtStart: number | undefined
    arrival: ReturnType<typeof classifyArrival>
    hasBody: boolean
    httpCursorAtArrival: number
    cdpCursorAtArrival: number
    siteConfigRev?: number
  }): Promise<{ safe: SafeRequestProjection; raw?: RequestDescriptor['raw']; releaseDecoded: () => void; decodeBudgetExceeded?: boolean }> => {
    const { req, url, seq, t, kind, prefixBuf, bodyComplete, transport, transportReasons, liveAtStart, genAtStart, arrival, hasBody } = params
    const hdrs = params.effectiveHeaders ?? req.headers
    const sanUrl = url ? sanitizeUrl(url, { projection, vault }) : sanitizeUrl(req.url ?? '/', { projection, vault })

    const destInfo = sanitizeDestHeader(hdrs)
    const dest = destInfo.dest
    let vaultRedactions = sanUrl.vaultRedactions + arrival.sem.vaultRedactions + destInfo.vaultRedactions
    let from: string | undefined
    if (typeof hdrs.referer === 'string' && hdrs.referer) {
      const sanFrom = sanitizeUrl(hdrs.referer, { projection, vault })
      from = sanFrom.url
      vaultRedactions += sanFrom.vaultRedactions
    }

    const reqType = normalizeContentType(typeof hdrs['content-type'] === 'string' ? hdrs['content-type'] : undefined, vault)
    const isWrite = arrival.isWrite || (SAFE_METHODS.has(arrival.sem.wireMethod) && (hasBody || prefixBuf.length > 0))
    const liveOrChanged = liveAtStart || isLiveNow() || (genAtStart !== undefined && liveGen?.() !== genAtStart)

    let decodeRes = undefined
    let decodedCharge = 0
    let decodeBudgetExceeded = false
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
        if (decodeRes.budgetExceeded) decodeBudgetExceeded = true
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
      transportReasons,
      isWrite,
      isAuth: arrival.isAuth,
      isLive: liveAfterDecode,
      projection,
      vault,
      sampleBudgetOk: sampleBytes < maxSampleBytes,
    })
    vaultRedactions += extracted.vaultRedactions

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
      ...(arrival.sem.hdrConflict && { hdrConflict: true as const }),
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
      ...(vaultRedactions > 0 && { vaultRedactions }),
      cdpCursor: params.cdpCursorAtArrival,
      httpCursor: params.httpCursorAtArrival,
      ...(params.siteConfigRev !== undefined && { siteConfigRev: params.siteConfigRev }),
      ...(liveAtStart && { live: true as const }),
      ...(extracted.reqBody !== undefined && { reqBody: extracted.reqBody }),
      ...(extracted.reqTrunc && { reqTrunc: true as const }),
      ...(extracted.reqOmitted && { reqOmitted: extracted.reqOmitted }),
    }

    const raw: RequestDescriptor['raw'] | undefined = url && !liveAfterDecode
      ? {
          url: url.href,
          ...(extracted.parsedBody !== undefined && { parsedBody: extracted.parsedBody }),
          ...(extracted.rawBodyText !== undefined && { rawBodyText: extracted.rawBodyText }),
          ...(arrival.declaredBytes !== undefined && { declaredBytes: arrival.declaredBytes }),
        }
      : undefined

    return { safe, raw, releaseDecoded, ...(decodeBudgetExceeded && { decodeBudgetExceeded: true }) }
  }

  const runPolicyHook = async (
    hook: PolicyHookConfig,
    descriptor: RequestDescriptor,
    parentSignal: AbortSignal,
    cdpCursorAtArrival: number,
    httpCursorAtArrival: number,
  ): Promise<{ decision: PolicyDecision; busy?: boolean }> => {
    const decisionId = crypto.randomUUID()
    const deadlineDuration = hook.deadlineMs ?? 20_000
    const deadlineMs = Date.now() + deadlineDuration
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

    const isValidDecision = (dec: unknown): dec is PolicyDecision =>
      Boolean(dec && typeof (dec as any).action === 'string' && ['allow', 'deny', 'escalate', 'requireApproval'].includes((dec as any).action))

    // Per-call child AbortController aborted on parent disconnect OR deadline timeout
    const hookAbort = new AbortController()
    const onParentAbort = () => hookAbort.abort()
    if (parentSignal.aborted) hookAbort.abort()
    else parentSignal.addEventListener('abort', onParentAbort, { once: true })

    const ctx: PolicyContext = {
      decisionId,
      signal: hookAbort.signal,
      deadlineMs,
      intent: opts?.auditV2?.intent,
      recentCdpCursor: cdpCursorAtArrival,
      recentHttpCursor: httpCursorAtArrival,
    }

    // 1. Optional explicit synchronous Stage-1 pre-check (never consumes async hook slot!)
    if (hook.checkSync) {
      let syncRes: PolicyDecision | undefined
      let isThenable = false
      try {
        syncRes = hook.checkSync(descriptor, ctx)
        if (syncRes !== undefined) {
          isThenable = typeof (syncRes as any)?.then === 'function'
        }
      } catch {
        parentSignal.removeEventListener('abort', onParentAbort)
        return { decision: makeErrorDecision() }
      }
      if (syncRes !== undefined) {
        if (isThenable) {
          Promise.resolve(syncRes).catch(() => {})
          hookAbort.abort()
          parentSignal.removeEventListener('abort', onParentAbort)
          return { decision: makeErrorDecision() }
        }
        parentSignal.removeEventListener('abort', onParentAbort)
        if (!isValidDecision(syncRes)) return { decision: makeErrorDecision() }
        return { decision: { ...syncRes, decisionId } }
      }
    }

    // 2. Explicit sync-only evaluate() contract (fails closed if a Promise is returned)
    if (hook.sync === true) {
      let result: PolicyDecision | Promise<PolicyDecision>
      let isThenable = false
      try {
        result = hook.evaluate(descriptor, ctx)
        isThenable = Boolean(result && typeof (result as any).then === 'function')
      } catch {
        parentSignal.removeEventListener('abort', onParentAbort)
        return { decision: makeErrorDecision() }
      }
      if (isThenable) {
        Promise.resolve(result).catch(() => {})
        hookAbort.abort()
        parentSignal.removeEventListener('abort', onParentAbort)
        return { decision: makeErrorDecision() }
      }
      parentSignal.removeEventListener('abort', onParentAbort)
      if (!isValidDecision(result)) return { decision: makeErrorDecision() }
      return { decision: { ...result, decisionId } }
    }

    // 3. Default async-capable evaluate(): reserve concurrency capacity BEFORE invoking evaluate()!
    if (hook.mode === 'enforce' && activeAsyncHooks >= maxConcurrentAsyncHooks) {
      parentSignal.removeEventListener('abort', onParentAbort)
      return { decision: makeErrorDecision(), busy: true }
    }

    activeAsyncHooks++
    let result: PolicyDecision | Promise<PolicyDecision>
    let isThenable = false
    try {
      result = hook.evaluate(descriptor, ctx)
      isThenable = Boolean(result && typeof (result as any).then === 'function')
    } catch {
      activeAsyncHooks = Math.max(0, activeAsyncHooks - 1)
      parentSignal.removeEventListener('abort', onParentAbort)
      return { decision: makeErrorDecision() }
    }

    // Synchronous return from an async-capable hook releases the reserved slot immediately
    if (!isThenable) {
      activeAsyncHooks = Math.max(0, activeAsyncHooks - 1)
      parentSignal.removeEventListener('abort', onParentAbort)
      if (!isValidDecision(result)) return { decision: makeErrorDecision() }
      return { decision: { ...result, decisionId } }
    }

    const promise = Promise.resolve(result)
    // Observe every promise so rejections never become unhandledProcessRejections
    promise.catch(() => {})

    // Slot stays occupied until underlying promise ACTUALLY settles (not released prematurely on timeout!)
    void promise.finally(() => {
      activeAsyncHooks = Math.max(0, activeAsyncHooks - 1)
      parentSignal.removeEventListener('abort', onParentAbort)
    }).catch(() => {})

    let timer: NodeJS.Timeout | undefined
    try {
      const settled = await Promise.race([
        promise,
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            hookAbort.abort()
            reject(new Error('policy timeout'))
          }, deadlineDuration)
          timer.unref?.()
        }),
      ])
      if (!settled || typeof settled.action !== 'string' || !['allow', 'deny', 'escalate', 'requireApproval'].includes(settled.action)) {
        return { decision: makeErrorDecision() }
      }
      return { decision: { ...settled, decisionId } }
    } catch {
      return { decision: makeErrorDecision() }
    } finally {
      clearTimeout(timer)
    }
  }

  const forward = (req: http.IncomingMessage, res: http.ServerResponse) => {
    if (admissionStopped || sealed) {
      res.writeHead(503, { 'content-type': 'text/plain', connection: 'close' }).end('rollforward-browser: session sealed\n')
      return
    }
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
      const up = (url!.protocol === 'https:' ? https : http).request(url!, buildOutboundSnapshot(req, url!), r => {
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
    const seq = ++seqCounter
    void handleV2Request(req, res, url, seq, t, startMs).catch(() => {
      const inflight = activeInFlight.get(seq)
      if (inflight) inflight.finalize()
      if (!res.headersSent && !res.destroyed) {
        res.writeHead(500, { 'content-type': 'text/plain' }).end('rollforward-browser: internal proxy error\n')
      }
    })
  }

  const handleV2Request = async (
    req: http.IncomingMessage,
    res: http.ServerResponse,
    url: URL | null,
    seq: number,
    t: string,
    startMs: number,
  ) => {
    const httpCursorAtArrival = cursorCounter
    const cdpCursorAtArrival = opts?.getCdpCursor?.() ?? 0
    const revAtStart = opts?.getSiteConfigRev?.()
    const liveAtStart = isLiveNow()
    const genAtStart = liveGen?.()

    try { vault?.ingestRequestHeaders(req.headers) } catch {}

    // Build effective outbound snapshot BEFORE deriving RequestDescriptor so site.headers are accounted for!
    const outboundSnap = url ? buildOutboundSnapshot(req, url) : undefined
    const arrival = classifyArrival(req, url, outboundSnap?.headers)

    // Single persistent cancellation owner installed at arrival and kept through dispatch
    const abortController = new AbortController()
    activeAbortControllers.add(abortController)
    const onReqErr = () => abortController.abort()
    const onResClose = () => { if (!res.writableFinished) abortController.abort() }
    req.on('error', onReqErr)
    res.on('close', onResClose)
    const cleanupCancellation = () => {
      activeAbortControllers.delete(abortController)
      req.off('error', onReqErr)
      res.off('close', onResClose)
    }

    // Register in activeInFlight IMMEDIATELY at arrival so seal() can NEVER lose an accepted request!
    let reserved = 0
    let terminalCommitted = false
    let cleanupExtra: (() => void) | undefined
    const stateRef = {
      status: 0,
      dispatch: 'not_dispatched' as 'not_dispatched' | 'dispatched' | 'unknown',
      reqBytes: 0,
      resBytes: 0,
      error: undefined as string | undefined,
    }

    const commitFallback = (reason: string, incomplete = true) => {
      if (terminalCommitted) return
      terminalCommitted = true
      activeInFlight.delete(seq)
      cleanupCancellation()
      cleanupExtra?.()
      const fb = buildFallbackProjection({
        req, url, seq, t, kind: 'http', arrival, liveAtStart,
        httpCursorAtArrival, cdpCursorAtArrival, siteConfigRev: revAtStart, reason,
      })
      const lateLive = !liveAtStart && (isLiveNow() || (genAtStart !== undefined && liveGen?.() !== genAtStart))
      appendV2Entry({
        ...fb,
        status: stateRef.status,
        ...(stateRef.error && { error: scrubText(stateRef.error, vault).text }),
        reqBytes: stateRef.reqBytes,
        resBytes: stateRef.resBytes,
        ms: Math.round(performance.now() - startMs),
        dispatch: stateRef.dispatch,
        ...(lateLive && { liveAtEnd: true as const }),
        ...(incomplete && { incomplete: true as const }),
      }, reserved)
      reserved = 0
    }

    activeInFlight.set(seq, {
      finalize: () => {
        incompleteAtSeal++
        if (stateRef.dispatch === 'dispatched') stateRef.dispatch = 'unknown'
        commitFallback('sealed-in-flight', true)
      },
    })

    const blocked = check(url)
    if (blocked) {
      const built = await buildSafeProjection({
        req, url, seq, t, kind: 'http', prefixBuf: Buffer.alloc(0), bodyComplete: false,
        transport: 'not-read', transportReasons: [], liveAtStart, genAtStart, arrival,
        hasBody: false, httpCursorAtArrival, cdpCursorAtArrival, siteConfigRev: revAtStart,
      })
      built.releaseDecoded()
      if (!terminalCommitted) {
        terminalCommitted = true
        activeInFlight.delete(seq)
        cleanupCancellation()
        appendV2Entry({ ...built.safe, status: 403, blocked, dispatch: 'not_dispatched', ms: Math.round(performance.now() - startMs) }, reserved)
        reserved = 0
      }
      res.writeHead(403, { 'content-type': 'text/plain' }).end(`rollforward-browser: ${blocked}: ${req.method} ${url?.href ?? req.url}\n`)
      return
    }

    // Reserve log space atomically before dispatching writes to site.hosts; other writes count-and-drop
    if (arrival.isWrite && isSiteHost(url)) {
      reserved = tryReserveLogSpace()
      if (reserved < 0) {
        reserved = 0
        terminalCommitted = true
        activeInFlight.delete(seq)
        cleanupCancellation()
        refusedFullCount++
        res.writeHead(403, { 'content-type': 'application/json', connection: 'close' }).end(JSON.stringify({ error: 'audit log full' }))
        return
      }
    }

    const activeHook = selectActiveHook(policyHook, liveAtStart)

    // ---- ENFORCE MODE ----
    if (activeHook && activeHook.mode === 'enforce') {
      let prefixBuf = Buffer.alloc(0)
      let overflowChunks: Buffer[] = []
      let bodyComplete = false
      let transport: 'complete' | 'truncated' | 'not-read' = 'not-read'
      let transportReasons: string[] = []
      let totalReqBytes = 0
      let releasePrefixBudget = () => {}
      let onEndFlag = () => req.readableEnded

      if (arrival.hasPotentialBody) {
        const pr = await readBoundedPrefix(req, inFlightTracker, clientId, sessionId, prefixTimeoutMs, abortController.signal)
        prefixBuf = pr.prefixBuf
        overflowChunks = pr.overflowChunks
        bodyComplete = pr.bodyComplete
        transport = pr.transport
        transportReasons = pr.reasons
        totalReqBytes = pr.totalReadBytes
        stateRef.reqBytes = totalReqBytes
        releasePrefixBudget = pr.releaseBudget
        onEndFlag = pr.onEndFlag
        cleanupExtra = () => releasePrefixBudget()

        if (pr.aborted || sealed) {
          releasePrefixBudget()
          if (!terminalCommitted) {
            const built = await buildSafeProjection({
              req, url, seq, t, kind: 'http', prefixBuf, bodyComplete: false,
              transport: 'truncated', transportReasons: [...transportReasons, 'client-abort'],
              liveAtStart, genAtStart, arrival, hasBody: totalReqBytes > 0,
              httpCursorAtArrival, cdpCursorAtArrival, siteConfigRev: revAtStart,
            })
            built.releaseDecoded()
            if (!terminalCommitted) {
              terminalCommitted = true
              activeInFlight.delete(seq)
              cleanupCancellation()
              appendV2Entry({ ...built.safe, status: 0, reqBytes: totalReqBytes, dispatch: 'not_dispatched', incomplete: true, ms: Math.round(performance.now() - startMs) }, reserved)
              reserved = 0
            }
          }
          return
        }

        if (pr.budgetExceeded) {
          releasePrefixBudget()
          const built = await buildSafeProjection({
            req, url, seq, t, kind: 'http', prefixBuf, bodyComplete: false,
            transport: 'truncated', transportReasons: [...transportReasons, 'inflight-budget'],
            liveAtStart, genAtStart, arrival, hasBody: totalReqBytes > 0,
            httpCursorAtArrival, cdpCursorAtArrival, siteConfigRev: revAtStart,
          })
          built.releaseDecoded()
          if (!terminalCommitted) {
            terminalCommitted = true
            activeInFlight.delete(seq)
            cleanupCancellation()
            appendV2Entry({ ...built.safe, status: 503, blocked: 'capture budget exceeded', dispatch: 'not_dispatched', ms: Math.round(performance.now() - startMs) }, reserved)
            reserved = 0
          }
          res.writeHead(503, { 'content-type': 'application/json', connection: 'close' }).end(JSON.stringify({ error: 'capture budget exceeded' }))
          return
        }
      }

      const built = await buildSafeProjection({
        req, effectiveHeaders: outboundSnap?.headers, url, seq, t, kind: 'http', prefixBuf, bodyComplete, transport, transportReasons,
        liveAtStart, genAtStart, arrival, hasBody: totalReqBytes > 0,
        httpCursorAtArrival, cdpCursorAtArrival, siteConfigRev: revAtStart,
      })
      cleanupExtra = () => { releasePrefixBudget(); built.releaseDecoded() }

      if (built.decodeBudgetExceeded) {
        releasePrefixBudget()
        built.releaseDecoded()
        if (!terminalCommitted) {
          terminalCommitted = true
          activeInFlight.delete(seq)
          cleanupCancellation()
          const ll = applyLateLive(built.safe, liveAtStart, genAtStart)
          appendV2Entry({ ...ll.safe, ...(ll.liveAtEnd && { liveAtEnd: true as const }), status: 503, blocked: 'capture budget exceeded', dispatch: 'not_dispatched', ms: Math.round(performance.now() - startMs) }, reserved)
          reserved = 0
        }
        res.writeHead(503, { 'content-type': 'application/json', connection: 'close' }).end(JSON.stringify({ error: 'capture budget exceeded' }))
        return
      }

      const hookRes = await runPolicyHook(activeHook, { safe: built.safe, raw: built.raw }, abortController.signal, cdpCursorAtArrival, httpCursorAtArrival)
      built.releaseDecoded()

      if (hookRes.busy) {
        releasePrefixBudget()
        if (!terminalCommitted) {
          terminalCommitted = true
          activeInFlight.delete(seq)
          cleanupCancellation()
          const ll = applyLateLive(built.safe, liveAtStart, genAtStart)
          appendV2Entry({ ...ll.safe, ...(ll.liveAtEnd && { liveAtEnd: true as const }), status: 503, blocked: 'policy busy', dispatch: 'not_dispatched', policy: hookRes.decision, ms: Math.round(performance.now() - startMs) }, reserved)
          reserved = 0
        }
        res.writeHead(503, { 'content-type': 'application/json', connection: 'close' }).end(JSON.stringify({ error: 'policy evaluator busy' }))
        return
      }

      if (abortController.signal.aborted || res.destroyed || (!req.readableEnded && req.destroyed) || req.socket?.destroyed || sealed || admissionStopped) {
        releasePrefixBudget()
        if (!terminalCommitted) {
          terminalCommitted = true
          activeInFlight.delete(seq)
          cleanupCancellation()
          const ll = applyLateLive(built.safe, liveAtStart, genAtStart)
          appendV2Entry({ ...ll.safe, ...(ll.liveAtEnd && { liveAtEnd: true as const }), status: 0, reqBytes: totalReqBytes, dispatch: 'not_dispatched', policy: hookRes.decision, incomplete: true, ms: Math.round(performance.now() - startMs) }, reserved)
          reserved = 0
        }
        return
      }

      if (hookRes.decision.action !== 'allow') {
        releasePrefixBudget()
        if (!terminalCommitted) {
          terminalCommitted = true
          activeInFlight.delete(seq)
          cleanupCancellation()
          const ll = applyLateLive(built.safe, liveAtStart, genAtStart)
          appendV2Entry({
            ...ll.safe,
            ...(ll.liveAtEnd && { liveAtEnd: true as const }),
            status: 403,
            blocked: 'blocked by policy',
            dispatch: 'not_dispatched',
            policy: hookRes.decision,
            ms: Math.round(performance.now() - startMs),
          }, reserved)
          reserved = 0
        }
        const respHeaders: Record<string, string> = { 'content-type': 'application/json' }
        if (!bodyComplete) respHeaders.connection = 'close'
        res.writeHead(403, respHeaders).end(JSON.stringify({
          error: 'blocked by policy',
          ruleId: hookRes.decision.ruleId,
          decisionId: hookRes.decision.decisionId,
        }))
        return
      }

      // Recheck BOTH host authorization AND siteConfigRev after async wait!
      const revChanged = revAtStart !== undefined && opts?.getSiteConfigRev?.() !== revAtStart
      const recheckBlocked = check(url) ?? (revChanged ? 'site config changed' : undefined)
      if (recheckBlocked) {
        releasePrefixBudget()
        if (!terminalCommitted) {
          terminalCommitted = true
          activeInFlight.delete(seq)
          cleanupCancellation()
          const ll = applyLateLive(built.safe, liveAtStart, genAtStart)
          appendV2Entry({
            ...ll.safe,
            ...(ll.liveAtEnd && { liveAtEnd: true as const }),
            status: 403,
            blocked: recheckBlocked,
            dispatch: 'not_dispatched',
            policy: hookRes.decision,
            ms: Math.round(performance.now() - startMs),
          }, reserved)
          reserved = 0
        }
        const respHeaders: Record<string, string> = { 'content-type': 'text/plain' }
        if (!bodyComplete) respHeaders.connection = 'close'
        res.writeHead(403, respHeaders).end(`rollforward-browser: ${recheckBlocked}: ${req.method} ${url?.href ?? req.url}\n`)
        return
      }

      dispatchUpstream({
        req, res, url: url!, outboundSnap: outboundSnap!, seq, t, startMs,
        liveAtStart, genAtStart, arrival, revAtStart,
        httpCursorAtArrival, cdpCursorAtArrival,
        getReserved: () => { const r = reserved; reserved = 0; return r },
        abortController, cleanupCancellation,
        isCommitted: () => terminalCommitted,
        markCommitted: () => { terminalCommitted = true; activeInFlight.delete(seq) },
        stateRef,
        preBuiltSafe: built.safe,
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

    // ---- OBSERVE OR SHADOW MODE ----
    // Uses the EXACT SAME 65,536-byte / 10 s cutoff state machine as PrefixReader!
    const teeChunks: Buffer[] = []
    let teeLen = 0
    let teeAcquired = 0
    let teeFrozen = !arrival.hasPotentialBody
    let teeComplete = false
    let teeTransport: 'complete' | 'truncated' | 'not-read' = arrival.hasPotentialBody ? 'truncated' : 'not-read'
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
      teeChunks.length = 0
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

    if (arrival.hasPotentialBody) {
      prefixTimer = setTimeout(() => freezeTee(false, 'prefix-timeout'), prefixTimeoutMs)
      prefixTimer.unref?.()
    } else {
      prefixFrozenResolve?.()
    }

    req.on('data', (chunk: Buffer) => {
      try {
        totalReqBytes += chunk.length
        stateRef.reqBytes = totalReqBytes
        if (!arrival.hasPotentialBody && teeTransport === 'not-read') {
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
        // Copy small slice so we never pin a giant backing buffer
        teeChunks.push(Buffer.from(chunk.subarray(0, take)))
        teeLen += take
        if (chunk.length > take) {
          freezeTee(false, '>64KiB')
        } else if (teeLen === MAX_PREFIX_BYTES) {
          // Exact 65,536-byte parity with PrefixReader!
          if (req.readableEnded) freezeTee(true)
          else freezeTee(false, '>=64KiB')
        }
      } catch {}
    })
    req.on('end', () => {
      if (!teeFrozen) freezeTee(true)
    })

    let shadowDecision: PolicyDecision | undefined
    let emittedEntryN: number | null = null
    let pendingShadowLate: PolicyDecision | undefined
    let consumersLeft = activeHook && activeHook.mode === 'shadow' ? 2 : 1
    let builtPromise: Promise<{ safe: SafeRequestProjection; raw?: RequestDescriptor['raw']; releaseDecoded: () => void }> | undefined
    let resolvedBuilt: { safe: SafeRequestProjection; raw?: RequestDescriptor['raw']; releaseDecoded: () => void } | undefined

    const releaseObserveConsumer = (built?: { safe: SafeRequestProjection; raw?: RequestDescriptor['raw']; releaseDecoded: () => void }) => {
      if (built) resolvedBuilt = built
      consumersLeft--
      if (consumersLeft <= 0) {
        resolvedBuilt?.releaseDecoded()
        releaseTeeBudget()
      }
    }

    const buildObserveDescriptor = async () => {
      const prefixBuf = teeChunks.length === 1 ? teeChunks[0] : Buffer.concat(teeChunks)
      teeChunks.length = 0 // drop chunk array immediately; charge stays held until all consumers finish!
      const built = await buildSafeProjection({
        req, effectiveHeaders: outboundSnap?.headers, url, seq, t, kind: 'http', prefixBuf,
        bodyComplete: teeComplete,
        transport: teeTransport,
        transportReasons: teeReasons,
        liveAtStart, genAtStart, arrival, hasBody: totalReqBytes > 0,
        httpCursorAtArrival, cdpCursorAtArrival, siteConfigRev: revAtStart,
      })
      resolvedBuilt = built
      if (budgetHit && built.safe.isWrite && (!built.safe.reqOmitted || built.safe.reqOmitted === 'policy-profile')) {
        built.safe.reqOmitted = 'budget'
      }
      if (sealed || consumersLeft <= 0) {
        built.releaseDecoded()
        releaseTeeBudget()
      }
      return built
    }

    const getBuilt = () => {
      if (!teeFrozen) freezeTee(req.readableEnded)
      return (builtPromise ??= buildObserveDescriptor())
    }

    cleanupExtra = () => {
      clearTimeout(prefixTimer)
      consumersLeft = 0
      if (builtPromise) void builtPromise.then(b => b.releaseDecoded(), () => {})
      resolvedBuilt?.releaseDecoded()
      releaseTeeBudget()
    }

    if (activeHook && activeHook.mode === 'shadow') {
      void prefixFrozenPromise.then(async () => {
        if (sealed) {
          if (builtPromise) void builtPromise.then(b => b.releaseDecoded(), () => {})
          releaseObserveConsumer()
          return
        }
        let desc: { safe: SafeRequestProjection; raw?: RequestDescriptor['raw']; releaseDecoded: () => void } | undefined
        try {
          desc = await getBuilt()
          const hr = await runPolicyHook(activeHook, { safe: desc.safe, raw: desc.raw }, abortController.signal, cdpCursorAtArrival, httpCursorAtArrival)
          shadowDecision = hr.decision
          if (emittedEntryN !== null && !sealed) {
            appendLateOutcome({
              rec: 'http_end',
              ref: emittedEntryN,
              t: new Date().toISOString(),
              ms: Math.round(performance.now() - startMs),
              policy: shadowDecision,
            })
          } else {
            pendingShadowLate = shadowDecision
          }
        } catch {
          // shadow failure never disrupts observe path
        } finally {
          releaseObserveConsumer(desc)
        }
      })
    } else {
      // Eagerly compute projection as soon as prefix is frozen so finalizeAtSeal() preserves bodyShape/actions!
      void prefixFrozenPromise.then(() => {
        if (!sealed) void getBuilt().catch(() => {})
      })
    }

    dispatchUpstream({
      req, res, url: url!, outboundSnap: outboundSnap!, seq, t, startMs,
      liveAtStart, genAtStart, arrival, revAtStart,
      httpCursorAtArrival, cdpCursorAtArrival,
      getReserved: () => { const r = reserved; reserved = 0; return r },
      abortController, cleanupCancellation,
      isCommitted: () => terminalCommitted,
      markCommitted: () => { terminalCommitted = true; activeInFlight.delete(seq) },
      stateRef,
      getLazySafe: async () => {
        let desc: { safe: SafeRequestProjection; raw?: RequestDescriptor['raw']; releaseDecoded: () => void } | undefined
        try {
          desc = await getBuilt()
          return desc.safe
        } finally {
          releaseObserveConsumer(desc)
        }
      },
      getResolvedSafe: () => resolvedBuilt?.safe,
      onSealFinalize: () => cleanupExtra(),
      getShadowDecision: () => shadowDecision ?? pendingShadowLate,
      onEmittedN: n => {
        emittedEntryN = n
        if (n !== null && pendingShadowLate && !sealed) {
          pendingShadowLate = undefined
        }
      },
      getReqBytes: () => totalReqBytes,
      onCleanupTee: () => { clearTimeout(prefixTimer) },
    })
  }

  const dispatchUpstream = (ctx: {
    req: http.IncomingMessage
    res: http.ServerResponse
    url: URL
    outboundSnap: ReturnType<typeof buildOutboundSnapshot>
    seq: number
    t: string
    startMs: number
    liveAtStart: boolean
    genAtStart: number | undefined
    arrival: ReturnType<typeof classifyArrival>
    revAtStart: number | undefined
    httpCursorAtArrival: number
    cdpCursorAtArrival: number
    getReserved: () => number
    abortController: AbortController
    cleanupCancellation: () => void
    isCommitted: () => boolean
    markCommitted: () => void
    stateRef: { status: number; dispatch: 'not_dispatched' | 'dispatched' | 'unknown'; reqBytes: number; resBytes: number; error?: string }
    preBuiltSafe?: SafeRequestProjection
    policyDecision?: PolicyDecision
    getLazySafe?: () => Promise<SafeRequestProjection>
    getResolvedSafe?: () => SafeRequestProjection | undefined
    onSealFinalize?: () => void
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
    const { req, res, url, outboundSnap, seq, t, startMs, liveAtStart, genAtStart, arrival, abortController, cleanupCancellation, stateRef } = ctx
    let resBytes = 0
    let replayTailBytes = 0
    let status = 0
    let resType: string | undefined
    let headerMs: number | undefined
    let errorMsg: string | undefined
    let emitStarted = false
    let emittedN: number | null = null
    let timedOutStream = false
    let reqDone = req.readableEnded || (!arrival.hasPotentialBody && !ctx.replay)
    let resDone = false
    let lateEmitted = false
    const pendingLateOutcomes: Array<Omit<LateOutcomeEntry, 'n' | 'ref'>> = []

    const totalReqBytes = () => ctx.replay ? ctx.replay.initialBytes + replayTailBytes : (ctx.getReqBytes?.() ?? 0)

    const flushPendingLate = () => {
      if (emittedN === null || sealed) return
      while (pendingLateOutcomes.length > 0) {
        const item = pendingLateOutcomes.shift()!
        appendLateOutcome({ ...item, ref: emittedN })
      }
    }

    const commitProjection = (safe: SafeRequestProjection, optsEmit: { incomplete?: true; forceDispatch?: 'unknown' }) => {
      if (ctx.isCommitted()) return
      ctx.markCommitted()
      const ms = Math.round(performance.now() - startMs)
      const lateLive = !liveAtStart && (isLiveNow() || (genAtStart !== undefined && liveGen?.() !== genAtStart))
      const finalSafe: SafeRequestProjection = { ...safe }
      if (lateLive && finalSafe.reqBody !== undefined) {
        delete finalSafe.reqBody
        finalSafe.reqOmitted = 'live'
      }
      const scrubbedErr = errorMsg ? scrubText(errorMsg, vault).text : undefined
      const decision = ctx.policyDecision ?? ctx.getShadowDecision?.()

      const n = appendV2Entry({
        ...finalSafe,
        status,
        ...(scrubbedErr && { error: scrubbedErr }),
        ...(resType && { resType }),
        reqBytes: totalReqBytes(),
        resBytes,
        ...(headerMs !== undefined && { headerMs }),
        ms,
        dispatch: optsEmit.forceDispatch ?? 'dispatched',
        ...(decision && { policy: decision }),
        ...(lateLive && { liveAtEnd: true as const }),
        ...(optsEmit.incomplete && { incomplete: true as const }),
      }, ctx.getReserved())

      emittedN = n
      ctx.onEmittedN?.(n)
      flushPendingLate()
    }

    const emitOnce = (optsEmit: { incomplete?: true }) => {
      if (emitStarted || ctx.isCommitted()) return
      emitStarted = true
      clearTimeout(streamTimer)
      ctx.onCleanupTee?.()

      if (ctx.preBuiltSafe) {
        commitProjection(ctx.preBuiltSafe, optsEmit)
      } else if (ctx.getLazySafe) {
        void ctx.getLazySafe().then(
          safe => commitProjection(safe, optsEmit),
          () => {
            // Never silently drop an observed request on projection error!
            const fb = buildFallbackProjection({
              req, url, seq, t, kind: 'http', arrival, liveAtStart,
              httpCursorAtArrival: ctx.httpCursorAtArrival, cdpCursorAtArrival: ctx.cdpCursorAtArrival,
              siteConfigRev: ctx.revAtStart, reason: 'extractor-error',
            })
            commitProjection(fb, optsEmit)
          },
        )
      }
    }

    const queueOrEmitLate = (incomplete?: true) => {
      if (!timedOutStream || !emitStarted || lateEmitted || sealed) return
      lateEmitted = true
      const scrubbedErr = errorMsg ? scrubText(errorMsg, vault).text : undefined
      const rec: Omit<LateOutcomeEntry, 'n' | 'ref'> = {
        rec: 'http_end',
        t: new Date().toISOString(),
        reqBytes: totalReqBytes(),
        resBytes,
        ms: Math.round(performance.now() - startMs),
        ...(scrubbedErr && { error: scrubbedErr }),
        ...(incomplete && { incomplete: true as const }),
      }
      if (emittedN !== null) appendLateOutcome({ ...rec, ref: emittedN })
      else pendingLateOutcomes.push(rec)
    }

    const tryCompleteBoth = () => {
      if (reqDone && resDone) {
        cleanupCancellation()
        if (!emitStarted) emitOnce({})
        else queueOrEmitLate()
      }
    }

    const streamTimer = setTimeout(() => {
      if (!emitStarted && !(reqDone && resDone)) {
        timedOutStream = true
        emitOnce({ incomplete: true })
      }
    }, streamTimeoutMs)
    streamTimer.unref?.()

    // Update seal finalizer so even during async projection, seal() commits synchronously and releases all budgets!
    activeInFlight.set(seq, {
      finalize: () => {
        if (ctx.isCommitted()) return
        incompleteAtSeal++
        clearTimeout(streamTimer)
        ctx.onCleanupTee?.()
        const safe = ctx.preBuiltSafe ?? ctx.getResolvedSafe?.() ?? buildFallbackProjection({
          req, url, seq, t, kind: 'http', arrival, liveAtStart,
          httpCursorAtArrival: ctx.httpCursorAtArrival, cdpCursorAtArrival: ctx.cdpCursorAtArrival,
          siteConfigRev: ctx.revAtStart, reason: 'sealed-in-flight',
        })
        ctx.onSealFinalize?.()
        ctx.replay?.releaseBudget()
        cleanupCancellation()
        commitProjection(safe, { incomplete: true, forceDispatch: 'unknown' })
      },
    })

    const up = (url.protocol === 'https:' ? https : http).request(url, outboundSnap, r => {
      headerMs = Math.round(performance.now() - startMs)
      status = r.statusCode ?? 0
      stateRef.status = status
      // Ingest Set-Cookie BEFORE projecting response Content-Type so newly issued tokens are scrubbed!
      try { vault?.ingestSetCookie(r.headers['set-cookie']) } catch {}
      resType = normalizeContentType(r.headers['content-type'], vault)

      const headers = { ...r.headers }
      for (const h of hopByHop) delete headers[h]
      if (!res.destroyed) {
        res.writeHead(status, headers)
        r.pipe(res)
      }

      r.on('data', (c: Buffer) => {
        resBytes += c.length
        stateRef.resBytes = resBytes
      })
      r.on('end', () => {
        resDone = true
        tryCompleteBoth()
        const dest = typeof req.headers['sec-fetch-dest'] === 'string' ? req.headers['sec-fetch-dest'] : undefined
        if (!liveAtStart && arrival.isWrite && !isLiveNow() && liveGen?.() === genAtStart) {
          opts?.onWriteDetail?.({ dest, isWrite: true })
          if (!opts?.onWriteDetail) onWrite?.()
        }
      })
      r.on('aborted', () => {
        resDone = true
        reqDone = true
        cleanupCancellation()
        errorMsg ||= 'upstream response aborted'
        stateRef.error = errorMsg
        if (!emitStarted) emitOnce({ incomplete: true })
        else queueOrEmitLate(true)
      })
      r.on('error', e => {
        resDone = true
        reqDone = true
        cleanupCancellation()
        errorMsg ||= e.message
        stateRef.error = errorMsg
        if (!emitStarted) emitOnce({ incomplete: true })
        else queueOrEmitLate(true)
        if (!res.destroyed) res.destroy()
      })
    })
    stateRef.dispatch = 'dispatched'
    activeUpstreams.add(up)
    up.on('close', () => activeUpstreams.delete(up))

    // Link arrival cancellation to upstream destruction
    const onAbort = () => {
      reqDone = true
      resDone = true
      up.destroy()
      cleanupCancellation()
      if (!emitStarted) emitOnce({ incomplete: true })
      else queueOrEmitLate(true)
    }
    if (abortController.signal.aborted) {
      onAbort()
      return
    }
    abortController.signal.addEventListener('abort', onAbort, { once: true })

    up.on('error', e => {
      reqDone = true
      resDone = true
      cleanupCancellation()
      errorMsg ||= e.message
      stateRef.error = errorMsg
      if (status === 0) {
        status = 502
        stateRef.status = 502
      }
      if (!emitStarted) emitOnce({})
      else queueOrEmitLate(true)
      if (!res.headersSent && !res.destroyed) {
        res.writeHead(502, { 'content-type': 'text/plain' }).end(`rollforward-browser: ${e.message}\n`)
      } else if (!res.destroyed) {
        res.destroy()
      }
    })

    if (ctx.replay) {
      void replayChunksAndPipe(
        req,
        up,
        ctx.replay.chunks,
        ctx.replay.isEnded,
        n => { replayTailBytes += n; stateRef.reqBytes = totalReqBytes() },
        () => { reqDone = true; tryCompleteBoth() },
        () => ctx.replay!.releaseBudget(),
      ).catch(() => {
        ctx.replay!.releaseBudget()
        up.destroy()
      })
    } else {
      if (!reqDone) {
        req.once('end', () => { reqDone = true; tryCompleteBoth() })
      }
      req.pipe(up)
    }
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

    if (!v2Enabled) {
      const blocked = check(url)
      if (blocked) {
        recordLegacy(req, url, 403, { blocked })
        socket.end('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n')
        return
      }
      const uOpts = buildOutboundSnapshot(req, url!)
      uOpts.headers.connection = 'upgrade'
      uOpts.headers.upgrade = req.headers.upgrade
      const up = (url!.protocol === 'https:' ? https : http).request(url!, uOpts)
      activeUpstreams.add(up)
      up.on('close', () => activeUpstreams.delete(up))
      socket.on('close', () => up.destroy())
      up.on('upgrade', (r, upSocket, upHead) => {
        if (socket.destroyed) { upSocket.destroy(); return }
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
        r.resume()
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

    // ---- auditV2 / policyHook upgrade path ----
    const seq = ++seqCounter
    void (async () => {
      const httpCursorAtArrival = cursorCounter
      const cdpCursorAtArrival = opts?.getCdpCursor?.() ?? 0
      const revAtStart = opts?.getSiteConfigRev?.()
      const liveAtStart = isLiveNow()
      const genAtStart = liveGen?.()
      try { vault?.ingestRequestHeaders(req.headers) } catch {}

      const outboundSnap = url ? buildOutboundSnapshot(req, url) : undefined
      const arrival = classifyArrival(req, url, outboundSnap?.headers)

      const abortController = new AbortController()
      activeAbortControllers.add(abortController)
      const onSockAbort = () => abortController.abort()
      socket.once('close', onSockAbort)
      socket.once('end', onSockAbort)
      const cleanupAbort = () => {
        activeAbortControllers.delete(abortController)
        socket.off('close', onSockAbort)
        socket.off('end', onSockAbort)
      }

      let committed = false
      let emittedUpgradeN: number | null = null
      let reserved = 0
      let dispatchState: 'not_dispatched' | 'dispatched' | 'unknown' = 'not_dispatched'
      activeInFlight.set(seq, {
        finalize: () => {
          if (committed) return
          committed = true
          incompleteAtSeal++
          activeInFlight.delete(seq)
          cleanupAbort()
          const fb = buildFallbackProjection({
            req, url, seq, t, kind: 'upgrade', arrival, liveAtStart,
            httpCursorAtArrival, cdpCursorAtArrival, siteConfigRev: revAtStart, reason: 'sealed-in-flight',
          })
          emittedUpgradeN = appendV2Entry({ ...fb, status: 0, dispatch: dispatchState === 'dispatched' ? 'unknown' : 'not_dispatched', incomplete: true, ms: Math.round(performance.now() - startMs) }, reserved)
          reserved = 0
        },
      })

      const built = await buildSafeProjection({
        req, effectiveHeaders: outboundSnap?.headers, url, seq, t, kind: 'upgrade', prefixBuf: Buffer.alloc(0), bodyComplete: false,
        transport: 'not-read', transportReasons: [], liveAtStart, genAtStart, arrival,
        hasBody: false, httpCursorAtArrival, cdpCursorAtArrival, siteConfigRev: revAtStart,
      })
      built.releaseDecoded()

      const blocked = check(url)
      if (blocked) {
        if (!committed) {
          committed = true
          activeInFlight.delete(seq)
          cleanupAbort()
          emittedUpgradeN = appendV2Entry({ ...built.safe, status: 403, blocked, dispatch: 'not_dispatched', ms: Math.round(performance.now() - startMs) }, reserved)
          reserved = 0
        }
        socket.end('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n')
        return
      }

      if (arrival.isWrite && isSiteHost(url)) {
        reserved = tryReserveLogSpace()
        if (reserved < 0) {
          reserved = 0
          committed = true
          activeInFlight.delete(seq)
          cleanupAbort()
          refusedFullCount++
          const fullJson = JSON.stringify({ error: 'audit log full' })
          socket.end(`HTTP/1.1 403 Forbidden\r\ncontent-type: application/json\r\ncontent-length: ${Buffer.byteLength(fullJson)}\r\nconnection: close\r\n\r\n${fullJson}`)
          return
        }
      }

      const activeHook = selectActiveHook(policyHook, liveAtStart)
      let policyDecision: PolicyDecision | undefined
      if (activeHook) {
        if (activeHook.mode === 'enforce') {
          const hr = await runPolicyHook(activeHook, { safe: built.safe, raw: built.raw }, abortController.signal, cdpCursorAtArrival, httpCursorAtArrival)
          policyDecision = hr.decision
          if (hr.busy) {
            if (!committed) {
              committed = true
              activeInFlight.delete(seq)
              cleanupAbort()
              const ll = applyLateLive(built.safe, liveAtStart, genAtStart)
              emittedUpgradeN = appendV2Entry({ ...ll.safe, ...(ll.liveAtEnd && { liveAtEnd: true as const }), status: 503, blocked: 'policy busy', dispatch: 'not_dispatched', policy: policyDecision, ms: Math.round(performance.now() - startMs) }, reserved)
              reserved = 0
            }
            socket.end('HTTP/1.1 503 Service Unavailable\r\nconnection: close\r\n\r\n')
            return
          }
          if (abortController.signal.aborted || socket.destroyed || sealed || admissionStopped) {
            if (!committed) {
              committed = true
              activeInFlight.delete(seq)
              cleanupAbort()
              const ll = applyLateLive(built.safe, liveAtStart, genAtStart)
              emittedUpgradeN = appendV2Entry({ ...ll.safe, ...(ll.liveAtEnd && { liveAtEnd: true as const }), status: 0, dispatch: 'not_dispatched', policy: policyDecision, incomplete: true, ms: Math.round(performance.now() - startMs) }, reserved)
              reserved = 0
            }
            socket.destroy()
            return
          }
          if (policyDecision.action !== 'allow') {
            if (!committed) {
              committed = true
              activeInFlight.delete(seq)
              cleanupAbort()
              const ll = applyLateLive(built.safe, liveAtStart, genAtStart)
              emittedUpgradeN = appendV2Entry({ ...ll.safe, ...(ll.liveAtEnd && { liveAtEnd: true as const }), status: 403, blocked: 'blocked by policy', dispatch: 'not_dispatched', policy: policyDecision, ms: Math.round(performance.now() - startMs) }, reserved)
              reserved = 0
            }
            const bodyJson = JSON.stringify({ error: 'blocked by policy', ruleId: policyDecision.ruleId, decisionId: policyDecision.decisionId })
            socket.end(`HTTP/1.1 403 Forbidden\r\ncontent-type: application/json\r\ncontent-length: ${Buffer.byteLength(bodyJson)}\r\nconnection: close\r\n\r\n${bodyJson}`)
            return
          }
          const revChanged = revAtStart !== undefined && opts?.getSiteConfigRev?.() !== revAtStart
          const recheck = check(url) ?? (revChanged ? 'site config changed' : undefined)
          if (recheck) {
            if (!committed) {
              committed = true
              activeInFlight.delete(seq)
              cleanupAbort()
              const ll = applyLateLive(built.safe, liveAtStart, genAtStart)
              emittedUpgradeN = appendV2Entry({ ...ll.safe, ...(ll.liveAtEnd && { liveAtEnd: true as const }), status: 403, blocked: recheck, dispatch: 'not_dispatched', policy: policyDecision, ms: Math.round(performance.now() - startMs) }, reserved)
              reserved = 0
            }
            socket.end('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n')
            return
          }
        } else {
          void runPolicyHook(activeHook, { safe: built.safe, raw: built.raw }, abortController.signal, cdpCursorAtArrival, httpCursorAtArrival).then(hr => {
            policyDecision = hr.decision
            if (emittedUpgradeN !== null && !sealed) {
              appendLateOutcome({
                rec: 'http_end',
                ref: emittedUpgradeN,
                t: new Date().toISOString(),
                ms: Math.round(performance.now() - startMs),
                policy: policyDecision,
              })
            }
          }).catch(() => {})
        }
      }

      if (abortController.signal.aborted || socket.destroyed || sealed || admissionStopped) {
        if (!committed) {
          committed = true
          activeInFlight.delete(seq)
          cleanupAbort()
          const ll = applyLateLive(built.safe, liveAtStart, genAtStart)
          emittedUpgradeN = appendV2Entry({ ...ll.safe, ...(ll.liveAtEnd && { liveAtEnd: true as const }), status: 0, dispatch: 'not_dispatched', ...(policyDecision && { policy: policyDecision }), incomplete: true, ms: Math.round(performance.now() - startMs) }, reserved)
          reserved = 0
        }
        socket.destroy()
        return
      }

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
        try { vault?.ingestSetCookie(r.headers['set-cookie']) } catch {}
        if (!committed) {
          committed = true
          activeInFlight.delete(seq)
          cleanupAbort()
          const ll = applyLateLive(built.safe, liveAtStart, genAtStart)
          emittedUpgradeN = appendV2Entry({ ...ll.safe, ...(ll.liveAtEnd && { liveAtEnd: true as const }), status: 101, dispatch: 'dispatched', ...(policyDecision && { policy: policyDecision }), ms: Math.round(performance.now() - startMs) }, reserved)
          reserved = 0
        }
        socket.write(`HTTP/1.1 101 Switching Protocols\r\n${Object.entries(r.headers).map(([k, v]) => `${k}: ${v}\r\n`).join('')}\r\n`)
        upSocket.write(head)
        socket.write(upHead)
        upSocket.pipe(socket).pipe(upSocket)
      })
      up.on('response', r => {
        r.resume()
        if (!committed) {
          committed = true
          activeInFlight.delete(seq)
          cleanupAbort()
          const ll = applyLateLive(built.safe, liveAtStart, genAtStart)
          emittedUpgradeN = appendV2Entry({ ...ll.safe, ...(ll.liveAtEnd && { liveAtEnd: true as const }), status: r.statusCode ?? 0, dispatch: 'dispatched', ...(policyDecision && { policy: policyDecision }), ms: Math.round(performance.now() - startMs) }, reserved)
          reserved = 0
        }
        socket.end(`HTTP/1.1 ${r.statusCode} ${r.statusMessage}\r\nconnection: close\r\n\r\n`)
      })
      up.on('error', e => {
        const err = scrubText(e.message, vault).text
        if (!committed) {
          committed = true
          activeInFlight.delete(seq)
          cleanupAbort()
          const ll = applyLateLive(built.safe, liveAtStart, genAtStart)
          emittedUpgradeN = appendV2Entry({ ...ll.safe, ...(ll.liveAtEnd && { liveAtEnd: true as const }), status: 502, error: err, dispatch: 'dispatched', ...(policyDecision && { policy: policyDecision }), ms: Math.round(performance.now() - startMs) }, reserved)
          reserved = 0
        }
        socket.end('HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n')
      })
      up.end()
    })().catch(() => {
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
    if (!v2Enabled) {
      recordLegacy(req, url, 417, { blocked: 'expectation failed' })
    } else {
      const seq = ++seqCounter
      const arrival = classifyArrival(req, url)
      const sanUrl = url ? sanitizeUrl(url, { projection, vault }) : sanitizeUrl(req.url ?? '/', { projection, vault })
      appendV2Entry({
        descV: DESC_V, redactV: REDACT_V, extractorV: EXTRACTOR_V,
        surface: 'browser', target: { site: siteName }, seq, t: new Date().toISOString(),
        kind: 'http', scheme: sanUrl.scheme, authority: sanUrl.authority, path: sanUrl.path, url: sanUrl.url,
        method: arrival.sem.wireMethod, effectiveMethod: arrival.sem.effectiveMethod, methodSource: arrival.sem.methodSource,
        isWrite: arrival.isWrite,
        ...(arrival.sem.hdr && { hdr: arrival.sem.hdr }),
        ...(arrival.sem.hdrConflict && { hdrConflict: true as const }),
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
    outer.closeAllConnections?.()
    inner.close()
    inner.closeAllConnections?.()
    for (const ac of activeAbortControllers) ac.abort()
    activeAbortControllers.clear()
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
      // Stop accepting new connections first; snapshot pending abort controllers before finalize() unregisters them,
      // finalize all in-flight entries with exact dispatch ('unknown' / 'not_dispatched'), then abort all controllers
      // and destroy every tunnel, downstream upgrade socket, and upstream cleanly!
      admissionStopped = true
      outer.close()
      inner.close()
      const pendingAborts = [...activeAbortControllers]
      activeAbortControllers.clear()
      for (const item of [...activeInFlight.values()]) item.finalize()
      activeInFlight.clear()
      for (const ac of pendingAborts) ac.abort()
      for (const ac of activeAbortControllers) ac.abort()
      activeAbortControllers.clear()
      if (v2Enabled) {
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
      }
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
      const v2Entries = log.filter((e): e is V2Entry | LateOutcomeEntry | SummaryEntry => typeof (e as any).n === 'number')
      const oldestCursor = v2Entries.length ? v2Entries[0].n : cursorCounter
      const out: LogRecord[] = []
      let pageBytes = 128 // envelope metadata overhead
      let lastIdx = -1
      for (let i = 0; i < v2Entries.length; i++) {
        const e = v2Entries[i]
        if (e.n <= after) continue
        const size = Buffer.byteLength(JSON.stringify(e), 'utf8') + 1
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
