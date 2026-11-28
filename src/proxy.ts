import http from 'node:http'
import https from 'node:https'
import tls from 'node:tls'
import net from 'node:net'
import dns from 'node:dns'
import { Duplex } from 'node:stream'
import { isBlocked } from './blocklists.ts'
import { page } from './page.ts'
import {
  DESC_V,
  EXTRACTOR_V,
  MAX_PREFIX_BYTES,
  SAFE_METHODS,
  decompressPrefix,
  extractSemantic,
  normalizeContentType,
  parseSemanticMethods,
  type BodyOmittedReason,
  type SharedSafeRequestProjection,
} from './extract.ts'
import {
  REDACT_V,
  SecretVault,
  isAuthUrl,
  sanitizeUrl,
  scrubDeep,
  scrubText,
  truncateUtf8HeadTail,
} from './redact.ts'

export { DESC_V }

export type AuditV2Config = {
  v: 2
  cdp?: boolean
  hud?: boolean
  shots?: boolean
  intent?: { run: number; series?: string; taskSummary?: string }
}

export type SafeRequestProjection = SharedSafeRequestProjection & {
  cdpCursor?: number
  httpCursor?: number
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
  droppedGets: number
  refusedFullCount: number
  incompleteAtSeal: number
  droppedLateOutcomes?: number
}

export type LogRecord = V2Entry | LateOutcomeEntry | SummaryEntry
export type Entry = V2Entry

export class ByteBudget {
  private used = 0
  readonly maxBytes: number

  constructor(maxBytes = 32 * 1024 * 1024) {
    this.maxBytes = maxBytes
  }

  tryAcquire(bytes: number): boolean {
    if (bytes <= 0) return true
    if (this.used + bytes > this.maxBytes) return false
    this.used += bytes
    return true
  }

  release(bytes: number): void {
    if (bytes > 0) this.used = Math.max(0, this.used - bytes)
  }

  getUsedBytes(): number {
    return this.used
  }
}

export type ProxyV2Options = {
  siteName?: string
  auditV2?: AuditV2Config
  vault?: SecretVault
  getCdpCursor?: () => number
  isLiveOrCooldown?: () => boolean
  byteBudget?: ByteBudget
  prefixTimeoutMs?: number
  streamTimeoutMs?: number
  maxLogBytes?: number
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

const ALLOWED_FETCH_DESTS = new Set([
  'audio', 'audioworklet', 'document', 'embed', 'empty', 'fencedframe', 'font', 'frame',
  'iframe', 'image', 'manifest', 'object', 'paintworklet', 'report', 'script',
  'serviceworker', 'sharedworker', 'style', 'track', 'video', 'webidentity', 'worker', 'xslt',
])

const MAX_ENTRY_BYTES = 12 * 1024
const MAX_PAGE_BYTES = 4 * 1024 * 1024

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
  const sem = parseSemanticMethods(method, headers)
  let hdr = sem.hdr
  if (headers['soapaction'] !== undefined) {
    const raw = headers['soapaction']
    hdr = { ...hdr, soapaction: scrubText(truncateUtf8HeadTail(Array.isArray(raw) ? raw.join(',') : raw, 256)).text }
  }
  return { ...sem, hdr, hasOverride: sem.hdr !== undefined }
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
  const vault = opts?.vault
  const siteName = opts?.siteName ?? (site.start_url ? URL.parse(site.start_url)?.hostname : undefined) ?? site.hosts[0] ?? 'site'
  const byteBudget = opts?.byteBudget ?? new ByteBudget()
  const prefixTimeoutMs = opts?.prefixTimeoutMs ?? 10_000
  const streamTimeoutMs = opts?.streamTimeoutMs ?? 35_000
  const maxLogBytes = opts?.maxLogBytes ?? 6 * 1024 * 1024
  const isLiveNow = opts?.isLiveOrCooldown ?? isLive

  let seqCounter = 0
  let cursorCounter = 0
  let logBytes = 0
  let inflightSiteWrites = 0
  let droppedGets = 0
  let refusedFullCount = 0
  let incompleteAtSeal = 0
  let droppedLateOutcomes = 0
  let admissionStopped = false
  let sealed = false
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

  const isLateLive = (liveAtStart: boolean, genAtStart: number | undefined): boolean =>
    !liveAtStart && (isLiveNow() || (genAtStart !== undefined && liveGen?.() !== genAtStart))

  const tryReserveSiteWrite = (): boolean => {
    if (logBytes + (inflightSiteWrites + 1) * MAX_ENTRY_BYTES > maxLogBytes) return false
    inflightSiteWrites++
    return true
  }

  const appendV2Entry = (entryWithoutN: Omit<V2Entry, 'n'>, hadSiteWriteReservation = false): number | null => {
    if (hadSiteWriteReservation) inflightSiteWrites = Math.max(0, inflightSiteWrites - 1)
    if (sealed) return null

    const draft: V2Entry = { n: cursorCounter + 1, ...entryWithoutN }
    const scrubbed = scrubDeep(draft, vault)
    const bytes = Buffer.byteLength(JSON.stringify(scrubbed), 'utf8')
    const avail = maxLogBytes - logBytes - inflightSiteWrites * MAX_ENTRY_BYTES
    const isSiteWrite = scrubbed.isWrite && matches(site.hosts, scrubbed.authority.split(':')[0])

    if (bytes > avail && !hadSiteWriteReservation) {
      if (!isSiteWrite) droppedGets++
      else refusedFullCount++
      return null
    }

    scrubbed.n = ++cursorCounter
    log.push(scrubbed)
    logBytes += bytes
    return scrubbed.n
  }

  const appendLateOutcome = (rec: Omit<LateOutcomeEntry, 'n'>): void => {
    if (sealed) return
    const full = scrubDeep({ n: cursorCounter + 1, ...rec }, vault)
    const bytes = Buffer.byteLength(JSON.stringify(full), 'utf8')
    if (logBytes + bytes > maxLogBytes + 64 * 1024) {
      droppedLateOutcomes++
      return
    }
    full.n = ++cursorCounter
    log.push(full)
    logBytes += bytes
  }

  const buildProjection = (params: {
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
  }): SafeRequestProjection => {
    const { req, url, seq, t, kind, arrival, liveAtStart, genAtStart } = params
    const hdrs = params.effectiveHeaders ?? req.headers
    const sanUrl = url ? sanitizeUrl(url) : sanitizeUrl(req.url ?? '/')
    const dest = sanitizeDest(hdrs)
    const from = typeof hdrs.referer === 'string' && hdrs.referer ? sanitizeUrl(hdrs.referer).url : undefined
    const prefixBuf = params.prefixBuf ?? Buffer.alloc(0)
    const transport = params.transport ?? 'not-read'
    const bodyComplete = params.bodyComplete ?? false
    const isWrite = arrival.isWrite || (SAFE_METHODS.has(arrival.sem.wireMethod) && (Boolean(params.hasBody) || prefixBuf.length > 0))

    if (params.fallbackReason) {
      return {
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
        ...(arrival.sem.invalidOrConflictingOverride && { overrideInvalid: true as const }),
        ...(arrival.sem.attemptedDowngrade && { overrideDowngrade: true as const }),
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
      }
    }

    const reqType = normalizeContentType(typeof hdrs['content-type'] === 'string' ? hdrs['content-type'] : undefined)
    const liveOrChanged = liveAtStart || isLiveNow() || (genAtStart !== undefined && liveGen?.() !== genAtStart)
    const decodeRes = kind === 'http' && prefixBuf.length > 0 && !liveOrChanged
      ? decompressPrefix(
          prefixBuf,
          typeof hdrs['content-encoding'] === 'string' ? hdrs['content-encoding'] : undefined,
          bodyComplete,
          MAX_PREFIX_BYTES,
        )
      : undefined

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
      isLive: liveOrChanged,
    })

    return {
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
      ...(arrival.sem.invalidOrConflictingOverride && { overrideInvalid: true as const }),
      ...(arrival.sem.attemptedDowngrade && { overrideDowngrade: true as const }),
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
      ...(extracted.reqTrunc && { reqTrunc: true as const }),
      ...(extracted.reqOmitted && { reqOmitted: extracted.reqOmitted }),
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
      const safe = buildProjection({
        req, url, seq, t, kind: 'http', arrival, liveAtStart, genAtStart,
        httpCursorAtArrival, cdpCursorAtArrival,
      })
      appendV2Entry({ ...safe, status: 403, blocked, dispatch: 'not_dispatched', ms: Math.round(performance.now() - startMs) })
      res.writeHead(403, { 'content-type': 'text/plain' }).end(`rollforward-browser: ${blocked}: ${req.method} ${url?.href ?? req.url}\n`)
      return
    }

    let reserved = false
    if (arrival.isWrite && isSiteHost(url)) {
      if (!tryReserveSiteWrite()) {
        refusedFullCount++
        res.writeHead(403, { 'content-type': 'application/json', connection: 'close' }).end(JSON.stringify({ error: 'audit log full' }))
        return
      }
      reserved = true
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

    const releaseTee = () => {
      clearTimeout(prefixTimer)
      if (teeAcquired > 0) {
        byteBudget.release(teeAcquired)
        teeAcquired = 0
      }
      teeChunks.length = 0
    }

    const freezeTee = (complete: boolean, reason?: string) => {
      if (teeFrozen) return
      teeFrozen = true
      clearTimeout(prefixTimer)
      teeComplete = complete
      teeTransport = complete ? 'complete' : 'truncated'
      if (reason && !teeReasons.includes(reason)) teeReasons.push(reason)
    }

    if (arrival.hasPotentialBody) {
      prefixTimer = setTimeout(() => freezeTee(false, 'prefix-timeout'), prefixTimeoutMs)
      prefixTimer.unref()
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
      if (!byteBudget.tryAcquire(take)) {
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

    // 2. Dispatch upstream + single synchronous finalize-once path + seal hook
    let resBytes = 0
    let status = 0
    let resType: string | undefined
    let headerMs: number | undefined
    let errorMsg: string | undefined
    let committed = false
    let emittedN: number | null = null
    let timedOutStream = false
    let reqDone = req.readableEnded || !arrival.hasPotentialBody
    let resDone = false
    let lateEmitted = false

    const finalizeOnce = (extra: { incomplete?: true; forceDispatch?: 'unknown' }) => {
      if (committed) return
      committed = true
      clearTimeout(streamTimer)
      activeInFlight.delete(seq)
      if (!teeFrozen) freezeTee(req.readableEnded)
      const prefixBuf = teeChunks.length === 1 ? teeChunks[0] : Buffer.concat(teeChunks)
      releaseTee()
      const safe = buildProjection({
        req, effectiveHeaders: outboundSnap?.headers, url, seq, t, kind: 'http',
        arrival, liveAtStart, genAtStart, httpCursorAtArrival, cdpCursorAtArrival,
        prefixBuf, bodyComplete: teeComplete, transport: teeTransport, transportReasons: teeReasons,
        hasBody: totalReqBytes > 0,
      })
      if (budgetHit && safe.isWrite && (!safe.reqOmitted || safe.reqOmitted === 'policy-profile')) {
        safe.reqOmitted = 'budget'
      }
      const lateLive = isLateLive(liveAtStart, genAtStart)
      const scrubbedErr = errorMsg ? truncateUtf8HeadTail(scrubText(errorMsg).text, 256) : undefined
      const ownRes = reserved
      reserved = false
      emittedN = appendV2Entry({
        ...safe,
        status,
        ...(scrubbedErr && { error: scrubbedErr }),
        ...(resType && { resType }),
        reqBytes: totalReqBytes,
        resBytes,
        ...(headerMs !== undefined && { headerMs }),
        ms: Math.round(performance.now() - startMs),
        dispatch: extra.forceDispatch ?? 'dispatched',
        ...(lateLive && { liveAtEnd: true as const }),
        ...(extra.incomplete && { incomplete: true as const }),
      }, ownRes)
    }

    const emitLate = (incomplete?: true) => {
      if (!timedOutStream || !committed || emittedN === null || lateEmitted || sealed) return
      lateEmitted = true
      const scrubbedErr = errorMsg ? truncateUtf8HeadTail(scrubText(errorMsg).text, 256) : undefined
      appendLateOutcome({
        rec: 'http_end',
        ref: emittedN,
        t: new Date().toISOString(),
        reqBytes: totalReqBytes,
        resBytes,
        ms: Math.round(performance.now() - startMs),
        ...(scrubbedErr && { error: scrubbedErr }),
        ...(incomplete && { incomplete: true as const }),
      })
    }

    const tryComplete = () => {
      if (reqDone && resDone) {
        if (!committed) finalizeOnce({})
        else emitLate()
      }
    }

    const streamTimer = setTimeout(() => {
      if (!committed && !(reqDone && resDone)) {
        timedOutStream = true
        finalizeOnce({ incomplete: true })
      }
    }, streamTimeoutMs)
    streamTimer.unref()

    activeInFlight.set(seq, {
      finalize: () => {
        if (committed) return
        incompleteAtSeal++
        finalizeOnce({ incomplete: true, forceDispatch: 'unknown' })
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
        if (!liveAtStart && arrival.isWrite && !isLiveNow() && liveGen?.() === genAtStart) onWrite?.()
      })
      r.on('aborted', () => {
        resDone = true; reqDone = true
        errorMsg ||= 'upstream response aborted'
        if (!committed) finalizeOnce({ incomplete: true })
        else emitLate(true)
      })
      r.on('error', e => {
        resDone = true; reqDone = true
        errorMsg ||= e.message
        if (!committed) finalizeOnce({ incomplete: true })
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
      if (!committed) finalizeOnce({ incomplete: true })
      else emitLate(true)
    }
    req.on('error', onCancel)
    res.on('close', () => { if (!res.writableFinished) onCancel() })

    up.on('error', e => {
      reqDone = true; resDone = true
      errorMsg ||= e.message
      if (status === 0) status = 502
      if (!committed) finalizeOnce({})
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
    let reserved = false
    let dispatchState: 'not_dispatched' | 'dispatched' | 'unknown' = 'not_dispatched'

    const safe = buildProjection({
      req, effectiveHeaders: outboundSnap?.headers, url, seq, t, kind: 'upgrade',
      arrival, liveAtStart, genAtStart, httpCursorAtArrival, cdpCursorAtArrival,
    })

    const commitUpgrade = (extra: { status: number; blocked?: string; error?: string; dispatch?: 'not_dispatched' | 'dispatched' | 'unknown'; incomplete?: true }) => {
      if (committed) return
      committed = true
      activeInFlight.delete(seq)
      const lateLive = isLateLive(liveAtStart, genAtStart)
      const ownRes = reserved
      reserved = false
      appendV2Entry({
        ...safe,
        status: extra.status,
        ...(extra.blocked && { blocked: extra.blocked }),
        ...(extra.error && { error: truncateUtf8HeadTail(extra.error, 256) }),
        dispatch: extra.dispatch ?? dispatchState,
        ...(lateLive && { liveAtEnd: true as const }),
        ...(extra.incomplete && { incomplete: true as const }),
        ms: Math.round(performance.now() - startMs),
      }, ownRes)
    }

    const blocked = check(url)
    if (blocked) {
      commitUpgrade({ status: 403, blocked, dispatch: 'not_dispatched' })
      socket.end('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n')
      return
    }
    if (arrival.isWrite && isSiteHost(url)) {
      if (!tryReserveSiteWrite()) {
        committed = true
        refusedFullCount++
        const fullJson = JSON.stringify({ error: 'audit log full' })
        socket.end(`HTTP/1.1 403 Forbidden\r\ncontent-type: application/json\r\ncontent-length: ${Buffer.byteLength(fullJson)}\r\nconnection: close\r\n\r\n${fullJson}`)
        return
      }
      reserved = true
    }

    activeInFlight.set(seq, {
      finalize: () => {
        if (committed) return
        incompleteAtSeal++
        commitUpgrade({ status: 0, dispatch: dispatchState === 'dispatched' ? 'unknown' : 'not_dispatched', incomplete: true })
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
      commitUpgrade({ status: 101, dispatch: 'dispatched' })
      socket.write(`HTTP/1.1 101 Switching Protocols\r\n${Object.entries(r.headers).map(([k, v]) => `${k}: ${v}\r\n`).join('')}\r\n`)
      upSocket.write(head)
      socket.write(upHead)
      upSocket.pipe(socket).pipe(upSocket)
    })
    up.on('response', r => {
      r.resume()
      commitUpgrade({ status: r.statusCode ?? 0, dispatch: 'dispatched' })
      socket.end(`HTTP/1.1 ${r.statusCode} ${r.statusMessage}\r\nconnection: close\r\n\r\n`)
    })
    up.on('error', e => {
      commitUpgrade({ status: 502, error: scrubText(e.message).text, dispatch: 'dispatched' })
      socket.end('HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n')
    })
    up.end()
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
    const safe = buildProjection({
      req, url, seq, t: new Date().toISOString(), kind: 'http', arrival,
      liveAtStart: isLiveNow(), httpCursorAtArrival: cursorCounter, cdpCursorAtArrival: opts?.getCdpCursor?.() ?? 0,
      fallbackReason: 'expectation-failed',
    })
    appendV2Entry({ ...safe, status: 417, blocked: 'expectation failed', dispatch: 'not_dispatched' })
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
    inner.closeAllConnections()
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
        droppedGets,
        refusedFullCount,
        incompleteAtSeal,
        ...(droppedLateOutcomes > 0 && { droppedLateOutcomes }),
      }
      log.push(summary)
      sealed = true
      outer.closeAllConnections()
      inner.closeAllConnections()
      for (const sock of activeTunnels) sock.destroy()
      activeTunnels.clear()
      for (const sock of activeUpgradeSockets) sock.destroy()
      activeUpgradeSockets.clear()
      for (const up of activeUpstreams) up.destroy()
      activeUpstreams.clear()
      return { logCursor: cursorCounter, droppedGets, refusedFull: refusedFullCount }
    },
    getLogPage: (after: number, limit = 500) =>
      page(log, e => e.n, cursorCounter, after, Math.min(500, Math.max(1, limit)), MAX_PAGE_BYTES, droppedGets),
    getCurrentCursor: () => cursorCounter,
    clear: () => {
      log.length = 0
      logBytes = 0
      inflightSiteWrites = 0
    },
  }

  outer.listen(path)
  return outer
}
