import crypto from 'node:crypto'
import {
  sanitizeUrl,
  scrubText,
  truncateHeadTail,
  type ProjectionMode,
  type SecretVault,
} from './redact.ts'

const MAX_MSG_HEAD = 65_536
const MAX_MSG_TAIL = 4_096
const MAX_CONTROL_LEN = 125
const MAX_FRAME_LEN = 256 * 1024 * 1024 // 256 MiB sanity ceiling for 64-bit length field
const MAX_METHOD_NAMES = 256
const MAX_METHOD_NAME_LEN = 64
const MAX_COALESCE_SLOTS = 64
const MAX_CDP_LOG_BYTES = 2 * 1024 * 1024
const MAX_OVERFLOW_HIGH_SEV = 32
const MAX_SAMPLE_EXPR_LEN = 1024
const MAX_PAGE_BYTES = 4 * 1024 * 1024

export type CdpEntry = {
  n: number
  rec?: 'cdp'
  t: string
  lastT?: string
  count?: number
  conn: number
  cdpSession?: string
  method: string
  severity?: 'high'
  ambiguous?: true
  live?: true
  summary?: Record<string, unknown>
  vaultRedactions?: number
}

export type CdpTapSummary = {
  n: number
  rec: '_tap.summary'
  t: string
  methodCounts: Record<string, number>
  depthLimited: number
  droppedCdp: number
  droppedHighSeverity: number
  tapDisabledCount: number
}

export type CdpLogRecord = CdpEntry | CdpTapSummary

export type ParsedWsMessage = {
  opcode: number
  head: Buffer
  tail: Buffer
  totalBytes: number
  truncated: boolean
  sha256: string
}

// Hardened passive RFC 6455 client->browser frame parser (zero mutation).
export class WsFrameParser {
  private buf: Buffer = Buffer.alloc(0)
  private disabled = false
  private msgActive = false
  private msgOpcode = 0
  private msgHeadChunks: Buffer[] = []
  private msgHeadBytes = 0
  private msgTail: Buffer = Buffer.alloc(0)
  private msgTotalBytes = 0
  private msgHash: crypto.Hash | null = null
  private onMessage: (msg: ParsedWsMessage) => void
  private onError: (reason: string) => void

  constructor(onMessage: (msg: ParsedWsMessage) => void, onError: (reason: string) => void) {
    this.onMessage = onMessage
    this.onError = onError
  }

  private fail(reason: string) {
    if (this.disabled) return
    this.disabled = true
    this.buf = Buffer.alloc(0)
    this.msgHeadChunks = []
    this.msgTail = Buffer.alloc(0)
    this.msgHash = null
    this.onError(reason)
  }

  private appendMessagePayload(data: Buffer) {
    this.msgTotalBytes += data.length
    this.msgHash!.update(data)
    if (this.msgHeadBytes < MAX_MSG_HEAD) {
      const take = Math.min(data.length, MAX_MSG_HEAD - this.msgHeadBytes)
      this.msgHeadChunks.push(data.subarray(0, take))
      this.msgHeadBytes += take
    }
    if (this.msgTotalBytes > MAX_MSG_HEAD) {
      if (data.length >= MAX_MSG_TAIL) {
        this.msgTail = Buffer.from(data.subarray(data.length - MAX_MSG_TAIL))
      } else {
        const combined = Buffer.concat([this.msgTail, data])
        this.msgTail = combined.length > MAX_MSG_TAIL ? combined.subarray(combined.length - MAX_MSG_TAIL) : combined
      }
    }
  }

  feed(chunk: Buffer): void {
    if (this.disabled || !chunk.length) return
    // Copy chunk before concatenating so caller buffers are never mutated.
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : Buffer.from(chunk)

    for (;;) {
      if (this.buf.length < 2) return
      const b0 = this.buf[0]
      const b1 = this.buf[1]
      const fin = (b0 & 0x80) !== 0
      const rsv = b0 & 0x70
      const opcode = b0 & 0x0f
      const masked = (b1 & 0x80) !== 0
      const len7 = b1 & 0x7f

      if (rsv !== 0) return this.fail(`non-zero RSV bits: 0x${rsv.toString(16)}`)
      const isControl = opcode >= 0x8
      if (opcode > 0xa || (opcode >= 0x3 && opcode <= 0x7)) return this.fail(`invalid opcode: ${opcode}`)
      if (isControl && !fin) return this.fail('fragmented control frame')

      let offset = 2
      let payloadLen = len7
      if (len7 === 126) {
        if (this.buf.length < 4) return
        payloadLen = this.buf.readUInt16BE(2)
        offset = 4
      } else if (len7 === 127) {
        if (this.buf.length < 10) return
        const big = this.buf.readBigUInt64BE(2)
        if ((this.buf[2] & 0x80) !== 0 || big > BigInt(MAX_FRAME_LEN)) {
          return this.fail('64-bit frame length overflow')
        }
        payloadLen = Number(big)
        offset = 10
      }

      if (isControl && payloadLen > MAX_CONTROL_LEN) return this.fail(`control frame too large: ${payloadLen}`)

      const maskBytes = masked ? 4 : 0
      const totalFrameLen = offset + maskBytes + payloadLen
      if (this.buf.length < totalFrameLen) return

      const payload = Buffer.allocUnsafe(payloadLen)
      if (masked) {
        const mask = this.buf.subarray(offset, offset + 4)
        const src = this.buf.subarray(offset + 4, totalFrameLen)
        for (let i = 0; i < payloadLen; i++) payload[i] = src[i] ^ mask[i & 3]
      } else {
        this.buf.copy(payload, 0, offset, totalFrameLen)
      }
      this.buf = this.buf.subarray(totalFrameLen)

      if (isControl) {
        // Interleaved Ping/Pong/Close allowed cleanly; ignore payload.
        continue
      }

      if (opcode === 0x0) {
        if (!this.msgActive) return this.fail('unexpected continuation frame')
        this.appendMessagePayload(payload)
      } else {
        // 0x1 text or 0x2 binary (treated identically)
        if (this.msgActive) return this.fail('new data frame while fragmented message open')
        this.msgActive = true
        this.msgOpcode = opcode
        this.msgHeadChunks = []
        this.msgHeadBytes = 0
        this.msgTail = Buffer.alloc(0)
        this.msgTotalBytes = 0
        this.msgHash = crypto.createHash('sha256')
        this.appendMessagePayload(payload)
      }

      if (fin) {
        const msg: ParsedWsMessage = {
          opcode: this.msgOpcode,
          head: Buffer.concat(this.msgHeadChunks),
          tail: this.msgTail,
          totalBytes: this.msgTotalBytes,
          truncated: this.msgTotalBytes > MAX_MSG_HEAD,
          sha256: this.msgHash!.digest('hex'),
        }
        this.msgActive = false
        this.msgHeadChunks = []
        this.msgHeadBytes = 0
        this.msgTail = Buffer.alloc(0)
        this.msgTotalBytes = 0
        this.msgHash = null
        this.onMessage(msg)
      }
    }
  }
}

// Check duplicate top-level `method` or `sessionId` keys in a JSON object.
function hasDuplicateTopLevelKeys(text: string): boolean {
  let i = 0
  const len = text.length
  const skipWs = () => {
    while (i < len && (text[i] === ' ' || text[i] === '\t' || text[i] === '\r' || text[i] === '\n')) i++
  }
  const readStr = (): string | null => {
    if (text[i] !== '"') return null
    const start = i
    i++
    let esc = false
    while (i < len) {
      if (text[i] === '\\') { esc = true; i += 2; continue }
      if (text[i] === '"') {
        i++
        const raw = text.slice(start, i)
        if (!esc) return raw.slice(1, -1)
        try { return JSON.parse(raw) } catch { return raw.slice(1, -1) }
      }
      i++
    }
    return null
  }
  skipWs()
  if (text[i] !== '{') return false
  i++
  let depth = 1
  const seen = new Set<string>()
  let expectKey = true
  while (i < len && depth > 0) {
    skipWs()
    if (i >= len) break
    const ch = text[i]
    if (ch === '{' || ch === '[') { depth++; expectKey = false; i++; continue }
    if (ch === '}' || ch === ']') { depth--; i++; continue }
    if (ch === '"') {
      const s = readStr()
      if (s === null) return false
      if (depth === 1 && expectKey) {
        if ((s === 'method' || s === 'sessionId') && seen.has(s)) return true
        seen.add(s)
        expectKey = false
      }
      continue
    }
    if (depth === 1 && ch === ',') { expectKey = true; i++; continue }
    if (depth === 1 && ch === ':') { expectKey = false; i++; continue }
    i++
  }
  return false
}

const HIGH_SEVERITY_METHODS = new Set([
  'Target.exposeDevToolsProtocol',
  'Runtime.addBinding',
  'Runtime.compileScript',
  'Runtime.runScript',
  'Debugger.evaluateOnCallFrame',
  'Debugger.setScriptSource',
  'Page.setDocumentContent',
  'DOM.setOuterHTML',
  'DOM.setAttributeValue',
])

const CONTROL_KEYS = new Set([
  'Enter', 'Escape', 'Tab',
  'F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12',
])

const NAV_SIMPLE_METHODS = new Set(['Page.reload', 'Page.goBack', 'Page.goForward', 'Target.closeTarget'])
const NET_SIMPLE_METHODS = new Set([
  'Network.deleteCookies', 'Storage.clearCookies', 'Fetch.enable',
  'Network.setRequestInterception', 'Browser.setDownloadBehavior',
  'Page.setDownloadBehavior', 'Page.printToPDF',
])

const hash64 = (s: string) => crypto.createHash('sha256').update(s).digest('hex').slice(0, 16)

function summarizeArg(arg: unknown, includePreview: boolean, vault?: SecretVault, previewBudget?: { left: number }): { item: Record<string, unknown>; vaultRedactions: number } {
  let vaultRedactions = 0
  if (!arg || typeof arg !== 'object') return { item: { type: typeof arg }, vaultRedactions }
  const a = arg as Record<string, unknown>
  if (typeof a.objectId === 'string') return { item: { type: 'handle' }, vaultRedactions }
  if (typeof a.unserializableValue === 'string') return { item: { type: 'unserializable' }, vaultRedactions }
  const val = a.value
  if (val === null) return { item: { type: 'null' }, vaultRedactions }
  if (val === undefined) return { item: { type: 'undefined' }, vaultRedactions }
  if (typeof val === 'string') {
    const item: Record<string, unknown> = { type: 'string', len: val.length }
    if (includePreview && previewBudget && previewBudget.left > 0) {
      const s = scrubText(val, vault)
      vaultRedactions += s.vaultRedactions
      const take = Math.min(previewBudget.left, 256)
      const prev = truncateHeadTail(s.text, take, Math.floor(take * 0.75), Math.floor(take * 0.25))
      item.preview = prev
      previewBudget.left -= prev.length
    }
    return { item, vaultRedactions }
  }
  if (typeof val === 'number' || typeof val === 'boolean') return { item: { type: typeof val }, vaultRedactions }
  if (Array.isArray(val)) return { item: { type: 'array', len: val.length }, vaultRedactions }
  if (typeof val === 'object') return { item: { type: 'object', keys: Object.keys(val as Record<string, unknown>).slice(0, 16) }, vaultRedactions }
  return { item: { type: typeof val }, vaultRedactions }
}

type CoalesceSlot = {
  key: string
  conn: number
  cdpSession?: string
  method: string
  firstT: string
  lastT: string
  count: number
  severity?: 'high'
  ambiguous?: true
  live?: true
  summary?: Record<string, unknown>
  vaultRedactions: number
  timer: NodeJS.Timeout
}

export type CdpTapOptions = {
  projection: ProjectionMode
  vault?: SecretVault
  isLive: () => boolean
  coalesceMs?: number
  maxBytes?: number
  injectedScriptSha256Allowlist?: Set<string>
  onEvent?: (entry: CdpEntry) => void
  onFileUpload?: () => void
}

export class CdpSessionTap {
  entries: CdpLogRecord[] = []
  private cursor = 0
  private bytes = 0
  private connSeq = 0
  private methodCounts: Record<string, number> = {}
  private distinctMethods = 0
  private depthLimited = 0
  private droppedCdp = 0
  private droppedHighSeverity = 0
  private overflowHighSevUsed = 0
  private tapDisabledCount = 0
  private slots = new Map<string, CoalesceSlot>()
  private lastKeyByConnSession = new Map<string, string>()
  private sealed = false
  private opts: CdpTapOptions
  private coalesceMs: number
  private maxBytes: number

  constructor(opts: CdpTapOptions) {
    this.opts = opts
    this.coalesceMs = opts.coalesceMs ?? 2_000
    this.maxBytes = opts.maxBytes ?? MAX_CDP_LOG_BYTES
  }

  get currentCursor(): number {
    return this.cursor
  }

  get dropped(): number {
    return this.droppedCdp
  }

  getRetainedBytes(): number {
    return this.bytes
  }

  private countMethod(method: string) {
    const safeName = method.length > MAX_METHOD_NAME_LEN ? method.slice(0, MAX_METHOD_NAME_LEN) : method
    if (safeName in this.methodCounts) {
      this.methodCounts[safeName]++
    } else if (this.distinctMethods < MAX_METHOD_NAMES) {
      this.methodCounts[safeName] = 1
      this.distinctMethods++
    } else {
      this.methodCounts._unknown_other = (this.methodCounts._unknown_other ?? 0) + 1
    }
  }

  private appendRecord(rec: Omit<CdpEntry, 'n'>): CdpEntry | null {
    if (this.sealed) return null
    const serialized = JSON.stringify({ ...rec, n: this.cursor + 1 })
    const size = Buffer.byteLength(serialized)
    if (this.bytes + size > this.maxBytes) {
      if (rec.severity === 'high' && this.overflowHighSevUsed < MAX_OVERFLOW_HIGH_SEV) {
        this.overflowHighSevUsed++
      } else {
        this.droppedCdp++
        if (rec.severity === 'high') this.droppedHighSeverity++
        return null
      }
    }
    const entry: CdpEntry = { n: ++this.cursor, ...rec }
    this.entries.push(entry)
    this.bytes += size
    this.opts.onEvent?.(entry)
    return entry
  }

  private flushSlot(key: string) {
    const slot = this.slots.get(key)
    if (!slot) return
    clearTimeout(slot.timer)
    this.slots.delete(key)
    const csKey = `${slot.conn}:${slot.cdpSession ?? ''}`
    if (this.lastKeyByConnSession.get(csKey) === key) this.lastKeyByConnSession.delete(csKey)
    this.appendRecord({
      t: slot.firstT,
      ...(slot.count > 1 && { lastT: slot.lastT, count: slot.count }),
      conn: slot.conn,
      ...(slot.cdpSession && { cdpSession: slot.cdpSession }),
      method: slot.method,
      ...(slot.severity && { severity: slot.severity }),
      ...(slot.ambiguous && { ambiguous: true as const }),
      ...(slot.live && { live: true as const }),
      ...(slot.summary && { summary: slot.summary }),
      ...(slot.vaultRedactions > 0 && { vaultRedactions: slot.vaultRedactions }),
    })
  }

  private enqueue(
    conn: number,
    cdpSession: string | undefined,
    method: string,
    severity: 'high' | undefined,
    ambiguous: boolean,
    summary: Record<string, unknown> | undefined,
    vaultRedactions: number,
  ) {
    if (this.sealed) return
    const now = new Date().toISOString()
    const live = this.opts.isLive()
    const sig = hash64(JSON.stringify({ method, severity, ambiguous, live, summary }))
    const key = `${conn}:${cdpSession ?? ''}:${method}:${sig}`
    const csKey = `${conn}:${cdpSession ?? ''}`

    // Flush previous slot on same (conn, cdpSession) if a different command arrived
    const prevKey = this.lastKeyByConnSession.get(csKey)
    if (prevKey && prevKey !== key) {
      this.flushSlot(prevKey)
    }

    const existing = this.slots.get(key)
    if (existing) {
      existing.count++
      existing.lastT = now
      existing.vaultRedactions += vaultRedactions
      return
    }

    // Bound active coalescing slots at 64
    if (this.slots.size >= MAX_COALESCE_SLOTS) {
      const oldestKey = this.slots.keys().next().value
      if (oldestKey) this.flushSlot(oldestKey)
    }

    const timer = setTimeout(() => this.flushSlot(key), this.coalesceMs)
    timer.unref?.()
    this.slots.set(key, {
      key,
      conn,
      cdpSession,
      method,
      firstT: now,
      lastT: now,
      count: 1,
      severity,
      ambiguous: ambiguous ? true : undefined,
      live: live ? true : undefined,
      summary,
      vaultRedactions,
      timer,
    })
    this.lastKeyByConnSession.set(csKey, key)
  }

  private handleCommand(conn: number, rawText: string, cdpSessionFallback: string | undefined, depth: number, rawSha256?: string, rawTotalBytes?: number) {
    if (this.sealed) return
    let parsed: any
    try {
      parsed = JSON.parse(rawText)
    } catch {
      return
    }
    if (!parsed || typeof parsed !== 'object' || typeof parsed.method !== 'string') return

    const method: string = parsed.method
    const cdpSession: string | undefined = typeof parsed.sessionId === 'string' ? parsed.sessionId : cdpSessionFallback
    const params: Record<string, unknown> = parsed.params && typeof parsed.params === 'object' ? parsed.params : {}
    const ambiguous = hasDuplicateTopLevelKeys(rawText)
    const samples = this.opts.projection === 'semantic+samples'
    const vault = this.opts.vault

    this.countMethod(method)

    // Recursion for Target.sendMessageToTarget (max depth 2)
    if (method === 'Target.sendMessageToTarget' && typeof params.message === 'string') {
      if (depth >= 2) {
        this.depthLimited++
        this.enqueue(conn, cdpSession, method, 'high', ambiguous, { depthLimited: true }, 0)
        return
      }
      const innerSession = typeof params.sessionId === 'string' ? params.sessionId : cdpSession
      this.handleCommand(conn, params.message, innerSession, depth + 1)
      return
    }

    let severity: 'high' | undefined = ambiguous ? 'high' : undefined
    let summary: Record<string, unknown> | undefined
    let vaultRedactions = 0
    let capture = false

    const scrubUrlField = (u: string): string => {
      const res = sanitizeUrl(u, { projection: this.opts.projection, vault })
      vaultRedactions += res.vaultRedactions
      return res.url
    }

    const scrubSampleExpr = (expr: string): string => {
      const s = scrubText(expr, vault)
      vaultRedactions += s.vaultRedactions
      return truncateHeadTail(s.text, MAX_SAMPLE_EXPR_LEN, 768, 252)
    }

    if (method === 'Runtime.callFunctionOn') {
      capture = true
      const fn = typeof params.functionDeclaration === 'string' ? params.functionDeclaration : ''
      const args = Array.isArray(params.arguments) ? params.arguments : []
      const isPwUtility =
        fn.includes('utilityScript.evaluate') &&
        args.length >= 5 &&
        typeof (args[1] as any)?.value === 'boolean' &&
        typeof (args[2] as any)?.value === 'boolean' &&
        typeof (args[3] as any)?.value === 'string' &&
        typeof (args[4] as any)?.value === 'number'

      const isAllowlistedInjected = rawSha256 ? this.opts.injectedScriptSha256Allowlist?.has(rawSha256) === true : false

      if (isPwUtility) {
        const isFunction = (args[1] as any).value as boolean
        const returnByValue = (args[2] as any).value as boolean
        const expr = (args[3] as any).value as string
        const argc = (args[4] as any).value as number
        const userArgs = args.slice(5)
        // Exclude fill/type value previews even in semantic+samples
        const isFillOrType = /\b(?:fill|type)\b/i.test(expr)
        const previewBudget = { left: 1024 }
        const argSummary = userArgs.slice(0, 16).map(a => {
          const r = summarizeArg(a, samples && !isFillOrType, vault, previewBudget)
          vaultRedactions += r.vaultRedactions
          return r.item
        })
        summary = {
          wrapper: 'playwright-utility',
          isFunction,
          returnByValue,
          argc,
          exprLen: expr.length,
          exprHash64: hash64(expr),
          ...(argSummary.length > 0 && { argSummary }),
          ...(samples && { expr: scrubSampleExpr(expr) }),
        }
        if ((expr.length > 16_384 || (rawTotalBytes ?? 0) > 16_384) && !isAllowlistedInjected) {
          severity = 'high'
        }
      } else {
        const previewBudget = { left: 1024 }
        const argSummary = args.slice(0, 16).map(a => {
          const r = summarizeArg(a, samples, vault, previewBudget)
          vaultRedactions += r.vaultRedactions
          return r.item
        })
        summary = {
          wrapper: 'custom',
          fnLen: fn.length,
          fnHash64: hash64(fn),
          argCount: args.length,
          ...(argSummary.length > 0 && { argSummary }),
          ...(samples && { fn: scrubSampleExpr(fn) }),
        }
        if ((fn.length > 16_384 || (rawTotalBytes ?? 0) > 16_384) && !isAllowlistedInjected) {
          severity = 'high'
        }
      }
    } else if (method === 'Runtime.evaluate' || method === 'Page.addScriptToEvaluateOnNewDocument') {
      capture = true
      const expr = typeof params.expression === 'string' ? params.expression : typeof params.source === 'string' ? params.source : ''
      const isAllowlistedInjected = rawSha256 ? this.opts.injectedScriptSha256Allowlist?.has(rawSha256) === true : false
      summary = {
        exprLen: expr.length,
        exprHash64: hash64(expr),
        ...(samples && expr && { expr: scrubSampleExpr(expr) }),
      }
      if ((expr.length > 16_384 || (rawTotalBytes ?? 0) > 16_384) && !isAllowlistedInjected) {
        severity = 'high'
      }
    } else if (HIGH_SEVERITY_METHODS.has(method)) {
      capture = true
      severity = 'high'
      if (method === 'DOM.setAttributeValue') {
        const name = typeof params.name === 'string' ? params.name : ''
        summary = { name: name.slice(0, 128) }
      } else if (method === 'Runtime.addBinding') {
        summary = { name: typeof params.name === 'string' ? params.name.slice(0, 128) : '' }
      } else if (method === 'Runtime.compileScript' || method === 'Debugger.evaluateOnCallFrame' || method === 'Debugger.setScriptSource') {
        const expr = typeof params.expression === 'string' ? params.expression : typeof params.scriptSource === 'string' ? params.scriptSource : ''
        summary = { exprLen: expr.length, exprHash64: hash64(expr) }
      } else {
        summary = {}
      }
    } else if (method.startsWith('Debugger.setBreakpoint') && typeof params.condition === 'string' && params.condition.length > 0) {
      capture = true
      severity = 'high'
      summary = { conditionLen: params.condition.length, conditionHash64: hash64(params.condition) }
    } else if (method === 'Page.navigate' || method === 'Target.createTarget') {
      capture = true
      const rawUrl = typeof params.url === 'string' ? params.url : ''
      if (/^\s*javascript:/i.test(rawUrl)) {
        severity = 'high'
        summary = { url: 'javascript:[REDACTED]', exprLen: rawUrl.length, exprHash64: hash64(rawUrl) }
      } else {
        summary = { url: scrubUrlField(rawUrl) }
      }
    } else if (NAV_SIMPLE_METHODS.has(method)) {
      capture = true
      summary = {}
    } else if (method === 'DOM.setFileInputFiles') {
      capture = true
      const files = Array.isArray(params.files)
        ? params.files.filter((f): f is string => typeof f === 'string').slice(0, 32).map(f => {
            const s = scrubText(f, vault)
            vaultRedactions += s.vaultRedactions
            return s.text
          })
        : []
      summary = { files }
      this.opts.onFileUpload?.()
    } else if (method === 'Input.dispatchMouseEvent') {
      if (params.type === 'mousePressed') {
        capture = true
        summary = {
          button: typeof params.button === 'string' ? params.button : undefined,
          x: typeof params.x === 'number' ? Math.round(params.x) : undefined,
          y: typeof params.y === 'number' ? Math.round(params.y) : undefined,
        }
      }
    } else if (method === 'Input.insertText' || method === 'Input.imeSetComposition') {
      capture = true
      const text = typeof params.text === 'string' ? params.text : ''
      summary = { len: text.length }
    } else if (method === 'Input.dispatchKeyEvent') {
      if (params.type === 'char') {
        capture = true
        const text = typeof params.text === 'string' ? params.text : ''
        summary = { len: text.length }
      } else if ((params.type === 'keyDown' || params.type === 'rawKeyDown') && typeof params.key === 'string' && CONTROL_KEYS.has(params.key)) {
        capture = true
        summary = { key: params.key }
      }
    } else if (method === 'Network.setExtraHTTPHeaders') {
      capture = true
      const hdrs = params.headers && typeof params.headers === 'object' ? Object.keys(params.headers as Record<string, unknown>).slice(0, 64) : []
      summary = { headerNames: hdrs }
    } else if (method === 'Network.setCookie') {
      capture = true
      summary = {
        name: typeof params.name === 'string' ? params.name.slice(0, 128) : undefined,
        domain: typeof params.domain === 'string' ? params.domain.slice(0, 128) : undefined,
      }
    } else if (method === 'Storage.setCookies') {
      capture = true
      const cookies = Array.isArray(params.cookies)
        ? params.cookies.slice(0, 32).map(c => ({
            name: typeof (c as any)?.name === 'string' ? (c as any).name.slice(0, 128) : undefined,
            domain: typeof (c as any)?.domain === 'string' ? (c as any).domain.slice(0, 128) : undefined,
          }))
        : []
      summary = { cookies }
    } else if (method === 'DOMStorage.setDOMStorageItem') {
      capture = true
      const key = typeof params.key === 'string' ? scrubText(params.key.slice(0, 128), vault) : { text: '', vaultRedactions: 0 }
      vaultRedactions += key.vaultRedactions
      summary = { key: key.text }
    } else if (method === 'Storage.setStorageItems') {
      capture = true
      const items = Array.isArray(params.items)
        ? params.items.slice(0, 32).map(it => {
            const k = typeof (it as any)?.key === 'string' ? (it as any).key.slice(0, 128) : ''
            const s = scrubText(k, vault)
            vaultRedactions += s.vaultRedactions
            return s.text
          })
        : []
      summary = { keys: items }
    } else if (NET_SIMPLE_METHODS.has(method)) {
      capture = true
      summary = {}
    }

    if (capture || ambiguous) {
      this.enqueue(conn, cdpSession, method, severity, ambiguous, summary, vaultRedactions)
    }
  }

  attachConnection(): { feed: (chunk: Buffer) => void; close: () => void } {
    const conn = ++this.connSeq
    let connDisabled = false
    const emitDisabled = (reason: string) => {
      if (connDisabled || this.sealed) return
      connDisabled = true
      this.tapDisabledCount++
      this.appendRecord({
        t: new Date().toISOString(),
        conn,
        method: '_tap.disabled',
        severity: 'high',
        summary: { reason: reason.slice(0, 200) },
      })
    }

    const parser = new WsFrameParser(
      msg => {
        if (this.sealed || connDisabled) return
        if (msg.truncated) {
          if (this.opts.injectedScriptSha256Allowlist?.has(msg.sha256)) {
            this.countMethod('_playwright.injectedScript')
            return
          }
          const headText = msg.head.toString('utf8')
          const methodMatch = /"method"\s*:\s*"([^"]{1,64})"/.exec(headText)
          const sessionMatch = /"sessionId"\s*:\s*"([^"]{1,128})"/.exec(headText)
          const extractedMethod = methodMatch?.[1]
          if (extractedMethod) this.countMethod(extractedMethod)
          this.appendRecord({
            t: new Date().toISOString(),
            conn,
            ...(sessionMatch?.[1] && { cdpSession: sessionMatch[1] }),
            method: '_tap.oversized',
            severity: 'high',
            summary: {
              bytes: msg.totalBytes,
              ...(extractedMethod && { innerMethod: extractedMethod }),
              sha256: msg.sha256.slice(0, 16),
            },
          })
          return
        }
        const text = msg.head.toString('utf8')
        this.handleCommand(conn, text, undefined, 0, msg.sha256, msg.totalBytes)
      },
      reason => emitDisabled(reason),
    )

    return {
      feed: (chunk: Buffer) => {
        if (connDisabled || this.sealed) return
        try {
          parser.feed(chunk)
        } catch (e: any) {
          emitDisabled(e?.message ?? 'tap exception')
        }
      },
      close: () => {
        for (const [key, slot] of [...this.slots.entries()]) {
          if (slot.conn === conn) this.flushSlot(key)
        }
      },
    }
  }

  seal(): { cdpCursor: number; droppedCdp: number } {
    if (this.sealed) return { cdpCursor: this.cursor, droppedCdp: this.droppedCdp }
    for (const key of [...this.slots.keys()]) this.flushSlot(key)
    const summary: CdpTapSummary = {
      n: ++this.cursor,
      rec: '_tap.summary',
      t: new Date().toISOString(),
      methodCounts: { ...this.methodCounts },
      depthLimited: this.depthLimited,
      droppedCdp: this.droppedCdp,
      droppedHighSeverity: this.droppedHighSeverity,
      tapDisabledCount: this.tapDisabledCount,
    }
    this.entries.push(summary)
    this.bytes += Buffer.byteLength(JSON.stringify(summary))
    this.sealed = true
    return { cdpCursor: this.cursor, droppedCdp: this.droppedCdp }
  }

  getPage(after: number, limit = 500): {
    oldestCursor: number
    nextCursor: number
    hasMore: boolean
    dropped: number
    entries: CdpLogRecord[]
  } {
    const cappedLimit = Math.min(500, Math.max(1, limit))
    const oldestCursor = this.entries.length ? this.entries[0].n : this.cursor
    const out: CdpLogRecord[] = []
    let pageBytes = 2 // []
    let lastCheckedIdx = -1

    for (let i = 0; i < this.entries.length; i++) {
      const e = this.entries[i]
      if (e.n <= after) continue
      const size = Buffer.byteLength(JSON.stringify(e)) + 1
      if (out.length > 0 && (out.length >= cappedLimit || pageBytes + size > MAX_PAGE_BYTES)) {
        break
      }
      out.push(e)
      pageBytes += size
      lastCheckedIdx = i
    }

    const hasMore = lastCheckedIdx >= 0 && lastCheckedIdx < this.entries.length - 1
    const nextCursor = out.length > 0 ? out[out.length - 1].n : Math.max(after, oldestCursor)
    return {
      oldestCursor,
      nextCursor,
      hasMore,
      dropped: this.droppedCdp,
      entries: out,
    }
  }

  clear(): void {
    for (const slot of this.slots.values()) clearTimeout(slot.timer)
    this.slots.clear()
    this.lastKeyByConnSession.clear()
    this.entries = []
    this.bytes = 0
  }
}

// Passive uncompressed /view/drive observer for SecretVault ONLY (never logged).
export function createDriveVaultTap(vault: SecretVault): { feed: (chunk: Buffer) => void; close: () => void } {
  let disabled = false
  const parser = new WsFrameParser(
    msg => {
      if (disabled || msg.truncated) return
      let parsed: any
      try {
        parsed = JSON.parse(msg.head.toString('utf8'))
      } catch {
        return
      }
      if (!parsed || typeof parsed !== 'object' || typeof parsed.method !== 'string') return
      vault.onDriveEvent(parsed.method, parsed.params)
    },
    () => {
      disabled = true
    },
  )
  return {
    feed: (chunk: Buffer) => {
      if (disabled) return
      try {
        parser.feed(chunk)
      } catch {
        disabled = true
      }
    },
    close: () => {
      try {
        vault.flushDriveBuffer()
      } catch {}
    },
  }
}
