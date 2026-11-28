import crypto from 'node:crypto'
import { page } from './page.ts'
import {
  isDataLikeKey,
  isSensitiveValue,
  sanitizeUrl,
  scrubDeep,
  scrubStructuralKey,
  scrubText,
  truncateUtf8HeadTail,
  type ProjectionMode,
  type SecretVault,
} from './redact.ts'

const MAX_MSG_HEAD = 65_536
const MAX_MSG_TAIL = 4_096
const MAX_CONTROL_LEN = 125
const MAX_FRAME_LEN = 256 * 1024 * 1024
const MAX_METHOD_NAMES = 256
const MAX_METHOD_NAME_BYTES = 64
const MAX_COALESCE_SLOTS = 64
const MAX_CDP_LOG_BYTES = 2 * 1024 * 1024
const MAX_OVERFLOW_HIGH_SEV = 32
const MAX_NORMAL_ENTRY_BYTES = 4_096
const MAX_ANOMALY_ENTRY_BYTES = 2_048
const CDP_ANOMALY_RESERVE = MAX_OVERFLOW_HIGH_SEV * MAX_ANOMALY_ENTRY_BYTES // 64 KiB
const CDP_SUMMARY_RESERVE = 32 * 1024 // 32 KiB
const MAX_SAMPLE_EXPR_BYTES = 1024
const MAX_PAGE_BYTES = 4 * 1024 * 1024
const SAFE_CDP_IDENT_RE = /^[A-Za-z0-9_.:-]{1,64}$/

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
}

export type CdpTapSummary = {
  n: number
  rec: '_tap.summary'
  t: string
  methodCounts: Record<string, number>
  depthLimited: number
  droppedCdp: number
  droppedHighSeverity: number
}

export type CdpLogRecord = CdpEntry | CdpTapSummary

export type ParsedWsMessage = {
  opcode: number
  head: Buffer
  tail: Buffer
  totalBytes: number
  truncated: boolean
  budgetDropped?: boolean
  sniff?: string
  sha256: string
}

export type BudgetCharger = {
  tryAcquire: (bytes: number) => boolean
  release: (bytes: number) => void
}

const MAX_SNIFF_BYTES = 256

// Incremental O(N) RFC 6455 client->browser frame parser (zero mutation, strictly bounded <=70 KiB per connection).
// Never disables the tap on capture-budget exhaustion: drops payload buffering for the affected message only while
// preserving RFC 6455 frame tracking and sniffing the leading 256 bytes for method counting & anomaly reporting.
export class WsFrameParser {
  private disabled = false
  private state: 'hdr2' | 'len16' | 'len64' | 'mask' | 'payload' = 'hdr2'
  private hdrBuf = Buffer.alloc(8)
  private hdrPos = 0
  private hdrNeed = 2

  private frameFin = false
  private frameOpcode = 0
  private frameMasked = false
  private frameIsControl = false
  private framePayloadRem = 0
  private maskKey = Buffer.alloc(4)
  private maskPos = 0

  private msgActive = false
  private msgOpcode = 0
  private msgHead = Buffer.alloc(0)
  private msgHeadLen = 0
  private msgTail = Buffer.alloc(0)
  private msgTotalBytes = 0
  private msgBudgetDropped = false
  private msgSniff = Buffer.alloc(MAX_SNIFF_BYTES)
  private msgSniffLen = 0
  private msgHash: crypto.Hash | null = null
  private chargedBytes = 0

  private onMessage: (msg: ParsedWsMessage) => void
  private onError: (reason: string) => void
  private charger?: BudgetCharger

  constructor(onMessage: (msg: ParsedWsMessage) => void, onError: (reason: string) => void, charger?: BudgetCharger) {
    this.onMessage = onMessage
    this.onError = onError
    this.charger = charger
  }

  private releaseCharge() {
    if (this.chargedBytes > 0 && this.charger) {
      this.charger.release(this.chargedBytes)
      this.chargedBytes = 0
    }
  }

  private resetMsg() {
    this.msgActive = false
    this.msgHead = Buffer.alloc(0)
    this.msgHeadLen = 0
    this.msgTail = Buffer.alloc(0)
    this.msgTotalBytes = 0
    this.msgBudgetDropped = false
    this.msgSniffLen = 0
    this.msgHash = null
    this.releaseCharge()
  }

  private fail(reason: string) {
    if (this.disabled) return
    this.disabled = true
    this.resetMsg()
    this.onError(reason)
  }

  close() {
    this.resetMsg()
  }

  private appendMessagePayload(data: Buffer) {
    const prevTotal = this.msgTotalBytes
    this.msgTotalBytes += data.length
    this.msgHash!.update(data)
    if (this.msgSniffLen < MAX_SNIFF_BYTES) {
      const takeSniff = Math.min(data.length, MAX_SNIFF_BYTES - this.msgSniffLen)
      data.copy(this.msgSniff, this.msgSniffLen, 0, takeSniff)
      this.msgSniffLen += takeSniff
    }
    if (this.msgBudgetDropped) return

    let overflowOffset = 0
    if (this.msgHeadLen < MAX_MSG_HEAD) {
      const take = Math.min(data.length, MAX_MSG_HEAD - this.msgHeadLen)
      if (this.msgHead.length === 0) {
        const allocSize = Math.min(MAX_MSG_HEAD, Math.max(4096, take))
        if (this.charger && !this.charger.tryAcquire(allocSize)) {
          this.msgBudgetDropped = true
          return
        }
        this.chargedBytes += allocSize
        this.msgHead = Buffer.allocUnsafe(allocSize)
      } else if (this.msgHeadLen + take > this.msgHead.length) {
        const nextSize = Math.min(MAX_MSG_HEAD, Math.max(this.msgHead.length * 2, this.msgHeadLen + take))
        const delta = nextSize - this.msgHead.length
        if (this.charger && !this.charger.tryAcquire(delta)) {
          this.msgBudgetDropped = true
          return
        }
        this.chargedBytes += delta
        const next = Buffer.allocUnsafe(nextSize)
        this.msgHead.copy(next, 0, 0, this.msgHeadLen)
        this.msgHead = next
      }
      data.copy(this.msgHead, this.msgHeadLen, 0, take)
      this.msgHeadLen += take
      overflowOffset = take
    }
    if (this.msgTotalBytes > MAX_MSG_HEAD) {
      if (this.msgTail.length === 0) {
        if (this.charger && !this.charger.tryAcquire(MAX_MSG_TAIL)) {
          this.msgBudgetDropped = true
          return
        }
        this.chargedBytes += MAX_MSG_TAIL
        this.msgTail = Buffer.allocUnsafe(MAX_MSG_TAIL)
        if (prevTotal <= MAX_MSG_HEAD && this.msgHeadLen >= MAX_MSG_TAIL) {
          this.msgHead.copy(this.msgTail, 0, this.msgHeadLen - MAX_MSG_TAIL, this.msgHeadLen)
        }
      }
      const tailIn = overflowOffset > 0 ? data.subarray(overflowOffset) : data
      if (tailIn.length >= MAX_MSG_TAIL) {
        tailIn.copy(this.msgTail, 0, tailIn.length - MAX_MSG_TAIL, tailIn.length)
      } else if (tailIn.length > 0) {
        this.msgTail.copyWithin(0, tailIn.length, MAX_MSG_TAIL)
        tailIn.copy(this.msgTail, MAX_MSG_TAIL - tailIn.length, 0, tailIn.length)
      }
    }
  }

  private startPayload() {
    if (this.frameIsControl) {
      if (this.framePayloadRem === 0) {
        this.state = 'hdr2'
        this.hdrPos = 0
        this.hdrNeed = 2
      } else {
        this.state = 'payload'
      }
      return
    }

    if (this.frameOpcode === 0x0) {
      if (!this.msgActive) {
        this.fail('unexpected continuation frame')
        return
      }
    } else {
      if (this.msgActive) {
        this.fail('new data frame while fragmented message open')
        return
      }
      this.msgActive = true
      this.msgOpcode = this.frameOpcode
      this.msgHead = Buffer.alloc(0)
      this.msgHeadLen = 0
      this.msgTail = Buffer.alloc(0)
      this.msgTotalBytes = 0
      this.msgBudgetDropped = false
      this.msgSniffLen = 0
      this.msgHash = crypto.createHash('sha256')
    }

    if (this.framePayloadRem === 0) {
      this.finishFrame()
    } else {
      this.state = 'payload'
    }
  }

  private finishFrame() {
    if (!this.frameIsControl && this.frameFin) {
      const msg: ParsedWsMessage = {
        opcode: this.msgOpcode,
        head: this.msgHead.subarray(0, this.msgHeadLen),
        tail: this.msgTail,
        totalBytes: this.msgTotalBytes,
        truncated: this.msgTotalBytes > MAX_MSG_HEAD,
        ...(this.msgBudgetDropped && {
          budgetDropped: true,
          sniff: this.msgSniff.subarray(0, this.msgSniffLen).toString('utf8'),
        }),
        sha256: this.msgHash!.digest('hex'),
      }
      // Keep parser charge active while synchronous consumer reads msg, then release cleanly!
      try {
        this.onMessage(msg)
      } finally {
        this.resetMsg()
      }
    }
    this.state = 'hdr2'
    this.hdrPos = 0
    this.hdrNeed = 2
  }

  feed(chunk: Buffer): void {
    if (this.disabled || !chunk.length) return
    let off = 0
    const len = chunk.length

    while (off < len && !this.disabled) {
      if (this.state === 'hdr2' || this.state === 'len16' || this.state === 'len64' || this.state === 'mask') {
        const take = Math.min(this.hdrNeed - this.hdrPos, len - off)
        chunk.copy(this.hdrBuf, this.hdrPos, off, off + take)
        this.hdrPos += take
        off += take
        if (this.hdrPos < this.hdrNeed) return

        if (this.state === 'hdr2') {
          const b0 = this.hdrBuf[0]
          const b1 = this.hdrBuf[1]
          this.frameFin = (b0 & 0x80) !== 0
          const rsv = b0 & 0x70
          this.frameOpcode = b0 & 0x0f
          this.frameMasked = (b1 & 0x80) !== 0
          const len7 = b1 & 0x7f
          if (rsv !== 0) return this.fail(`non-zero RSV bits: 0x${rsv.toString(16)}`)
          if (!this.frameMasked) return this.fail('unmasked client frame')
          this.frameIsControl = this.frameOpcode >= 0x8
          if (this.frameOpcode > 0xa || (this.frameOpcode >= 0x3 && this.frameOpcode <= 0x7)) {
            return this.fail(`invalid opcode: ${this.frameOpcode}`)
          }
          if (this.frameIsControl && !this.frameFin) return this.fail('fragmented control frame')

          if (len7 < 126) {
            this.framePayloadRem = len7
            if (this.frameIsControl && len7 > MAX_CONTROL_LEN) return this.fail(`control frame too large: ${len7}`)
            if (this.frameMasked) {
              this.state = 'mask'
              this.hdrPos = 0
              this.hdrNeed = 4
            } else {
              this.startPayload()
            }
          } else if (len7 === 126) {
            if (this.frameIsControl) return this.fail('control frame too large')
            this.state = 'len16'
            this.hdrPos = 0
            this.hdrNeed = 2
          } else {
            if (this.frameIsControl) return this.fail('control frame too large')
            this.state = 'len64'
            this.hdrPos = 0
            this.hdrNeed = 8
          }
        } else if (this.state === 'len16') {
          this.framePayloadRem = this.hdrBuf.readUInt16BE(0)
          if (this.frameMasked) {
            this.state = 'mask'
            this.hdrPos = 0
            this.hdrNeed = 4
          } else {
            this.startPayload()
          }
        } else if (this.state === 'len64') {
          const big = this.hdrBuf.readBigUInt64BE(0)
          if ((this.hdrBuf[0] & 0x80) !== 0 || big > BigInt(MAX_FRAME_LEN)) {
            return this.fail('64-bit frame length overflow')
          }
          this.framePayloadRem = Number(big)
          if (this.frameMasked) {
            this.state = 'mask'
            this.hdrPos = 0
            this.hdrNeed = 4
          } else {
            this.startPayload()
          }
        } else if (this.state === 'mask') {
          this.hdrBuf.copy(this.maskKey, 0, 0, 4)
          this.maskPos = 0
          this.startPayload()
        }
      } else if (this.state === 'payload') {
        const avail = Math.min(this.framePayloadRem, len - off)
        if (this.frameIsControl) {
          // Control payload discarded without allocation
          off += avail
          this.framePayloadRem -= avail
          this.maskPos = (this.maskPos + avail) & 3
        } else {
          // Process in bounded <=4 KiB slices without allocating payload-sized buffers
          let rem = avail
          while (rem > 0 && !this.disabled) {
            const step = Math.min(rem, 4096)
            const slice = Buffer.allocUnsafe(step)
            if (this.frameMasked) {
              for (let i = 0; i < step; i++) {
                slice[i] = chunk[off + i] ^ this.maskKey[(this.maskPos + i) & 3]
              }
              this.maskPos = (this.maskPos + step) & 3
            } else {
              chunk.copy(slice, 0, off, off + step)
            }
            off += step
            rem -= step
            this.framePayloadRem -= step
            this.appendMessagePayload(slice)
          }
        }
        if (!this.disabled && this.framePayloadRem === 0) {
          this.finishFrame()
        }
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
const MOUSE_BUTTONS = new Set(['none', 'left', 'middle', 'right', 'back', 'forward'])
const NET_SIMPLE_METHODS = new Set([
  'Network.deleteCookies', 'Storage.clearCookies', 'Fetch.enable',
  'Network.setRequestInterception', 'Browser.setDownloadBehavior',
  'Page.setDownloadBehavior', 'Page.printToPDF',
])

const hash64 = (s: string) => crypto.createHash('sha256').update(s).digest('hex').slice(0, 16)

function scrubCdpIdent(raw: unknown, maxBytes = 64): string | undefined {
  if (typeof raw !== 'string' || !raw) return undefined
  const s = scrubText(raw).text
  if (s.includes('[REDACTED') || isSensitiveValue(s)) return '[REDACTED]'
  return truncateUtf8HeadTail(s, maxBytes)
}

function scrubCdpSessionId(raw: unknown): string | undefined {
  if (typeof raw !== 'string' || !raw) return undefined
  if (/^[A-Fa-f0-9_-]{1,40}$/.test(raw) && !isSensitiveValue(raw)) return raw
  return `sid:${hash64(raw)}`
}

function summarizeArg(
  arg: unknown,
  includePreview: boolean,
  vault?: SecretVault,
  previewBudgetBytes?: { left: number },
): { item: Record<string, unknown>; vaultRedactions: number } {
  let vaultRedactions = 0
  if (!arg || typeof arg !== 'object') return { item: { type: typeof arg }, vaultRedactions }
  const a = arg as Record<string, unknown>
  if (typeof a.objectId === 'string') return { item: { type: 'handle' }, vaultRedactions }
  if (typeof a.unserializableValue === 'string') return { item: { type: 'unserializable' }, vaultRedactions }
  const val = a.value
  if (val === null) return { item: { type: 'null' }, vaultRedactions }
  if (val === undefined) return { item: { type: 'undefined' }, vaultRedactions }
  if (typeof val === 'string') {
    const item: Record<string, unknown> = { type: 'string', len: Buffer.byteLength(val, 'utf8') }
    if (includePreview && previewBudgetBytes && previewBudgetBytes.left > 0) {
      const s = scrubText(val, vault)
      vaultRedactions += s.vaultRedactions
      const take = Math.min(previewBudgetBytes.left, 256)
      const prev = truncateUtf8HeadTail(s.text, take)
      const prevBytes = Buffer.byteLength(prev, 'utf8')
      if (prevBytes <= previewBudgetBytes.left) {
        item.preview = prev
        previewBudgetBytes.left -= prevBytes
      }
    }
    return { item, vaultRedactions }
  }
  if (typeof val === 'number' || typeof val === 'boolean') return { item: { type: typeof val }, vaultRedactions }
  if (Array.isArray(val)) return { item: { type: 'array', len: val.length }, vaultRedactions }
  // Type + keyCount ONLY for object arguments (never expose raw property names!)
  if (typeof val === 'object') return { item: { type: 'object', keyCount: Object.keys(val as Record<string, unknown>).length }, vaultRedactions }
  return { item: { type: typeof val }, vaultRedactions }
}

function capCdpRecordBytes(entry: CdpEntry, maxBytes: number): { entry: CdpEntry; bytes: number } {
  let bytes = Buffer.byteLength(JSON.stringify(entry), 'utf8')
  if (bytes <= maxBytes) return { entry, bytes }
  const copy: CdpEntry = { ...entry }
  if (copy.summary) {
    const slim: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(copy.summary)) {
      if (k === 'expr' || k === 'fn' || k === 'argSummary') continue
      slim[k] = typeof v === 'string' ? truncateUtf8HeadTail(v, 256) : v
    }
    copy.summary = slim
    bytes = Buffer.byteLength(JSON.stringify(copy), 'utf8')
    if (bytes <= maxBytes) return { entry: copy, bytes }
  }
  delete copy.summary
  bytes = Buffer.byteLength(JSON.stringify(copy), 'utf8')
  return { entry: copy, bytes }
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
  timer: NodeJS.Timeout
}

const DEFAULT_CDP_PARSER_BUDGET = 1024 * 1024 // 1 MiB dedicated per-session CDP parser budget (isolated from HTTP proxy & drive tap)
const RESERVED_PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

export type CdpTapOptions = {
  projection: ProjectionMode
  vault?: SecretVault
  isLive: () => boolean
  coalesceMs?: number
  maxBytes?: number
  maxParserBytes?: number
  injectedScriptSha256Allowlist?: Set<string>
  charger?: BudgetCharger
  onFileUpload?: () => void
}

export class CdpSessionTap {
  entries: CdpLogRecord[] = []
  private cursor = 0
  private bytes = 0
  private connSeq = 0
  private methodCounts: Record<string, number> = Object.create(null)
  private distinctMethods = 0
  private depthLimited = 0
  private droppedCdp = 0
  private droppedHighSeverity = 0
  private overflowHighSevUsed = 0
  private slots = new Map<string, CoalesceSlot>()
  private lastKeyByConnSession = new Map<string, string>()
  private sealed = false
  private opts: CdpTapOptions
  private coalesceMs: number
  private maxBytes: number
  private summaryReserve: number
  private anomalyReserve: number
  private parserUsedBytes = 0
  private parserMaxBytes: number

  constructor(opts: CdpTapOptions) {
    this.opts = opts
    this.coalesceMs = opts.coalesceMs ?? 2_000
    this.maxBytes = opts.maxBytes ?? MAX_CDP_LOG_BYTES
    this.parserMaxBytes = opts.maxParserBytes ?? DEFAULT_CDP_PARSER_BUDGET
    this.summaryReserve = Math.min(CDP_SUMMARY_RESERVE, Math.floor(this.maxBytes * 0.1))
    this.anomalyReserve = Math.min(CDP_ANOMALY_RESERVE, Math.floor(this.maxBytes * 0.15))
  }

  private getParserCharger(): BudgetCharger {
    if (this.opts.charger) return this.opts.charger
    return {
      tryAcquire: bytes => {
        if (bytes <= 0) return true
        if (this.parserUsedBytes + bytes > this.parserMaxBytes) return false
        this.parserUsedBytes += bytes
        return true
      },
      release: bytes => {
        if (bytes <= 0) return
        this.parserUsedBytes = Math.max(0, this.parserUsedBytes - bytes)
      },
    }
  }

  get currentCursor(): number {
    return this.cursor
  }

  get dropped(): number {
    return this.droppedCdp
  }

  private countMethod(rawMethod: string) {
    const vault = this.opts.vault
    const name = rawMethod
    if (RESERVED_PROTO_KEYS.has(name) || (vault && vault.scrub(name).count > 0)) {
      this.methodCounts._unknown_other = (this.methodCounts._unknown_other ?? 0) + 1
      return
    }
    if (!SAFE_CDP_IDENT_RE.test(name) || Buffer.byteLength(name, 'utf8') > MAX_METHOD_NAME_BYTES || isSensitiveValue(name)) {
      this.methodCounts._unknown_other = (this.methodCounts._unknown_other ?? 0) + 1
      return
    }
    if (Object.prototype.hasOwnProperty.call(this.methodCounts, name)) {
      this.methodCounts[name]++
    } else if (this.distinctMethods < MAX_METHOD_NAMES) {
      this.methodCounts[name] = 1
      this.distinctMethods++
    } else {
      this.methodCounts._unknown_other = (this.methodCounts._unknown_other ?? 0) + 1
    }
  }

  private appendRecord(rec: Omit<CdpEntry, 'n'>): CdpEntry | null {
    if (this.sealed) return null
    const normalCeiling = Math.max(0, this.maxBytes - this.summaryReserve - this.anomalyReserve)
    const hardCeiling = Math.max(0, this.maxBytes - this.summaryReserve)
    const draft: CdpEntry = { n: this.cursor + 1, ...rec }
    const isHigh = rec.severity === 'high'
    const capped = capCdpRecordBytes(draft, isHigh && this.bytes >= normalCeiling ? MAX_ANOMALY_ENTRY_BYTES : MAX_NORMAL_ENTRY_BYTES)

    if (this.bytes + capped.bytes > normalCeiling) {
      if (isHigh && this.overflowHighSevUsed < MAX_OVERFLOW_HIGH_SEV && this.bytes + capped.bytes <= hardCeiling) {
        this.overflowHighSevUsed++
      } else {
        this.droppedCdp++
        if (isHigh) this.droppedHighSeverity++
        return null
      }
    }

    capped.entry.n = ++this.cursor
    const scrubbed = scrubDeep(capped.entry, this.opts.vault)
    this.entries.push(scrubbed)
    this.bytes += capped.bytes
    return scrubbed
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
    })
  }

  private enqueue(
    conn: number,
    cdpSession: string | undefined,
    method: string,
    severity: 'high' | undefined,
    ambiguous: boolean,
    summary: Record<string, unknown> | undefined,
    forceLive = false,
  ) {
    if (this.sealed) return
    const now = new Date().toISOString()
    const live = forceLive || this.opts.isLive()
    const sig = hash64(JSON.stringify({ method, severity, ambiguous, live, summary }))
    const key = `${conn}:${cdpSession ?? ''}:${method}:${sig}`
    const csKey = `${conn}:${cdpSession ?? ''}`

    const prevKey = this.lastKeyByConnSession.get(csKey)
    if (prevKey && prevKey !== key) {
      this.flushSlot(prevKey)
    }

    const existing = this.slots.get(key)
    if (existing) {
      existing.count++
      existing.lastT = now
      return
    }

    if (this.slots.size >= MAX_COALESCE_SLOTS) {
      const oldestKey = this.slots.keys().next().value
      if (oldestKey) this.flushSlot(oldestKey)
    }

    const timer = setTimeout(() => this.flushSlot(key), this.coalesceMs)
    timer.unref()
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
      timer,
    })
    this.lastKeyByConnSession.set(csKey, key)
  }

  private handleCommand(conn: number, rawText: string, cdpSessionFallback: string | undefined, depth: number, rawSha256?: string, rawTotalBytes?: number, forceLive = false, onParsed?: (method: string, params: Record<string, unknown>) => void) {
    if (this.sealed) return
    let parsed: any
    try {
      parsed = JSON.parse(rawText)
    } catch {
      this.countMethod('_unparsed')
      this.enqueue(conn, cdpSessionFallback, '_tap.unparsed', 'high', false, { bytes: Buffer.byteLength(rawText, 'utf8') }, forceLive)
      return
    }
    if (!parsed || typeof parsed !== 'object' || typeof parsed.method !== 'string') {
      this.countMethod('_unparsed')
      return
    }

    const rawMethod: string = parsed.method
    const cdpSession = scrubCdpSessionId(typeof parsed.sessionId === 'string' ? parsed.sessionId : cdpSessionFallback)

    const params: Record<string, unknown> = parsed.params && typeof parsed.params === 'object' ? parsed.params : {}
    onParsed?.(rawMethod, params)
    const ambiguous = hasDuplicateTopLevelKeys(rawText)
    const samples = this.opts.projection === 'semantic+samples'

    this.countMethod(rawMethod)
    const safeMethod = scrubCdpIdent(rawMethod, MAX_METHOD_NAME_BYTES) ?? '_unknown'

    if (rawMethod === 'Target.sendMessageToTarget' && typeof params.message === 'string') {
      if (depth >= 2) {
        this.depthLimited++
        this.enqueue(conn, cdpSession, safeMethod, 'high', ambiguous, { depthLimited: true }, forceLive)
        return
      }
      const innerSession = typeof params.sessionId === 'string' ? params.sessionId : cdpSession
      this.handleCommand(conn, params.message, innerSession, depth + 1, undefined, undefined, forceLive, onParsed)
      return
    }

    let severity: 'high' | undefined = ambiguous ? 'high' : undefined
    let summary: Record<string, unknown> | undefined
    let capture = false

    const scrubSampleExpr = (expr: string): string =>
      truncateUtf8HeadTail(scrubText(expr).text, MAX_SAMPLE_EXPR_BYTES, 768, 252)

    if (rawMethod === 'Runtime.callFunctionOn') {
      capture = true
      const fn = typeof params.functionDeclaration === 'string' ? params.functionDeclaration : ''
      const fnLen = Buffer.byteLength(fn, 'utf8')
      const fnHash64 = hash64(fn)
      const args = Array.isArray(params.arguments) ? params.arguments : []
      const isAllowlistedInjected = rawSha256 ? this.opts.injectedScriptSha256Allowlist?.has(rawSha256) === true : false
      summary = {
        fnLen,
        fnHash64,
        argCount: args.length,
        ...(samples && fn && { fn: scrubSampleExpr(fn) }),
      }
      if ((fnLen > 16_384 || (rawTotalBytes ?? 0) > 16_384) && !isAllowlistedInjected) {
        severity = 'high'
      }
    } else if (rawMethod === 'Runtime.evaluate' || rawMethod === 'Page.addScriptToEvaluateOnNewDocument') {
      capture = true
      const expr = typeof params.expression === 'string' ? params.expression : typeof params.source === 'string' ? params.source : ''
      const isAllowlistedInjected = rawSha256 ? this.opts.injectedScriptSha256Allowlist?.has(rawSha256) === true : false
      summary = {
        exprLen: Buffer.byteLength(expr, 'utf8'),
        exprHash64: hash64(expr),
        ...(samples && expr && { expr: scrubSampleExpr(expr) }),
      }
      if ((Buffer.byteLength(expr, 'utf8') > 16_384 || (rawTotalBytes ?? 0) > 16_384) && !isAllowlistedInjected) {
        severity = 'high'
      }
    } else if (HIGH_SEVERITY_METHODS.has(rawMethod)) {
      capture = true
      severity = 'high'
      if (rawMethod === 'DOM.setAttributeValue' || rawMethod === 'Runtime.addBinding') {
        summary = { name: scrubCdpIdent(params.name, 128) ?? '' }
      } else if (rawMethod === 'Runtime.compileScript' || rawMethod === 'Debugger.evaluateOnCallFrame' || rawMethod === 'Debugger.setScriptSource') {
        const expr = typeof params.expression === 'string' ? params.expression : typeof params.scriptSource === 'string' ? params.scriptSource : ''
        summary = { exprLen: Buffer.byteLength(expr, 'utf8'), exprHash64: hash64(expr) }
      } else {
        summary = {}
      }
    } else if (rawMethod.startsWith('Debugger.setBreakpoint') && typeof params.condition === 'string' && params.condition.length > 0) {
      capture = true
      severity = 'high'
      summary = { conditionLen: Buffer.byteLength(params.condition, 'utf8'), conditionHash64: hash64(params.condition) }
    } else if (rawMethod === 'Page.navigate' || rawMethod === 'Target.createTarget') {
      capture = true
      const rawUrl = typeof params.url === 'string' ? params.url : ''
      const strippedUrl = rawUrl.trim().replace(/[\u0000-\u001f]+/g, '')
      const vault = this.opts.vault
      const rawHit = Boolean(vault && (vault.scrub(rawUrl).count > 0 || (strippedUrl !== rawUrl && vault.scrub(strippedUrl).count > 0)))
      let navUrl: string
      let extra: Record<string, unknown> = {}

      if (/^https?:/i.test(strippedUrl)) {
        const parsed = URL.parse(strippedUrl)
        navUrl = parsed ? sanitizeUrl(parsed, { projection: this.opts.projection }).url : `${/^https:/i.test(strippedUrl) ? 'https:' : 'http:'}//[REDACTED]`
      } else if (/^data:/i.test(strippedUrl)) {
        severity = 'high'
        const comma = strippedUrl.indexOf(',')
        const rawMeta = (comma >= 0 ? strippedUrl.slice(5, comma) : strippedUrl.slice(5)).split(';')[0].trim()
        const safeMime = !rawHit && /^[A-Za-z0-9.+-]+\/[A-Za-z0-9.+-]+$/.test(rawMeta) ? rawMeta.toLowerCase() : '[REDACTED]'
        navUrl = `data:${safeMime};len=${Buffer.byteLength(rawUrl, 'utf8')}`
      } else if (/^(?:javascript|vbscript):/i.test(strippedUrl)) {
        severity = 'high'
        const scheme = /^vbscript:/i.test(strippedUrl) ? 'vbscript' : 'javascript'
        navUrl = `${scheme}:[REDACTED]`
        extra = { exprLen: Buffer.byteLength(rawUrl, 'utf8'), exprHash64: hash64(rawUrl) }
      } else if (/^about:(?:blank|srcdoc)$/i.test(strippedUrl)) {
        navUrl = rawHit ? 'about:[REDACTED]' : strippedUrl.toLowerCase()
      } else {
        const schemeMatch = /^([a-z][a-z0-9+.-]{0,15}):/i.exec(strippedUrl)
        const rawScheme = schemeMatch ? schemeMatch[1].toLowerCase() : 'unknown'
        navUrl = rawHit ? '[REDACTED]' : `${rawScheme}:[REDACTED]`
        extra = { len: Buffer.byteLength(rawUrl, 'utf8') }
      }
      summary = { url: navUrl, ...extra }
    } else if (NAV_SIMPLE_METHODS.has(rawMethod)) {
      capture = true
      summary = {}
    } else if (rawMethod === 'DOM.setFileInputFiles') {
      capture = true
      const files = Array.isArray(params.files)
        ? params.files.filter((f): f is string => typeof f === 'string').slice(0, 32).map(f => truncateUtf8HeadTail(scrubText(f).text, 256))
        : []
      summary = { files }
      this.opts.onFileUpload?.()
    } else if (rawMethod === 'Input.dispatchMouseEvent') {
      if (params.type === 'mousePressed') {
        capture = true
        const rawBtn = typeof params.button === 'string' ? params.button : undefined
        summary = {
          button: rawBtn && MOUSE_BUTTONS.has(rawBtn) ? rawBtn : rawBtn ? 'other' : undefined,
          x: typeof params.x === 'number' ? Math.round(params.x) : undefined,
          y: typeof params.y === 'number' ? Math.round(params.y) : undefined,
        }
      }
    } else if (rawMethod === 'Input.insertText' || rawMethod === 'Input.imeSetComposition') {
      capture = true
      const text = typeof params.text === 'string' ? params.text : ''
      summary = { len: text.length }
    } else if (rawMethod === 'Input.dispatchKeyEvent') {
      if (params.type === 'char') {
        capture = true
        const text = typeof params.text === 'string' ? params.text : ''
        summary = { len: text.length }
      } else if ((params.type === 'keyDown' || params.type === 'rawKeyDown') && typeof params.key === 'string' && CONTROL_KEYS.has(params.key)) {
        capture = true
        summary = { key: params.key }
      }
    } else if (rawMethod === 'Network.setExtraHTTPHeaders') {
      capture = true
      const hdrs = params.headers && typeof params.headers === 'object'
        ? Object.keys(params.headers as Record<string, unknown>).slice(0, 64).map(k => truncateUtf8HeadTail(scrubStructuralKey(k).key, 64))
        : []
      summary = { headerNames: hdrs }
    } else if (rawMethod === 'Network.setCookie') {
      capture = true
      summary = { name: scrubCdpIdent(params.name, 64), domain: scrubCdpIdent(params.domain, 128) }
    } else if (rawMethod === 'Storage.setCookies') {
      capture = true
      const cookies = Array.isArray(params.cookies)
        ? params.cookies.slice(0, 32).map(c => ({
            name: scrubCdpIdent((c as any)?.name, 64),
            domain: scrubCdpIdent((c as any)?.domain, 128),
          }))
        : []
      summary = { cookies }
    } else if (rawMethod === 'DOMStorage.setDOMStorageItem') {
      capture = true
      const key = typeof params.key === 'string' ? scrubStructuralKey(params.key).key : ''
      summary = { key: truncateUtf8HeadTail(key, 64) }
    } else if (rawMethod === 'Storage.setStorageItems') {
      capture = true
      const items = Array.isArray(params.items)
        ? params.items.slice(0, 32).map(it => {
            const rawK = typeof (it as any)?.key === 'string' ? (it as any).key : ''
            return truncateUtf8HeadTail(scrubStructuralKey(rawK).key, 64)
          })
        : []
      summary = { keys: items }
    } else if (NET_SIMPLE_METHODS.has(rawMethod)) {
      capture = true
      summary = {}
    }

    if (capture || ambiguous) {
      this.enqueue(conn, cdpSession, safeMethod, severity, ambiguous, summary, forceLive)
    }
  }

  attachConnection(connOpts?: { live?: boolean; driveVault?: boolean; onError?: (reason: string) => void }): { feed: (chunk: Buffer) => void; close: () => void } {
    const conn = ++this.connSeq
    const forceLive = connOpts?.live === true
    const driveBuf = connOpts?.driveVault && this.opts.vault ? this.opts.vault.createDriveBuffer() : undefined
    let connFailed = false
    const failConn = (reason: string) => {
      if (connFailed) return
      connFailed = true
      driveBuf?.clear()
      connOpts?.onError?.(reason)
    }

    const parser = new WsFrameParser(
      msg => {
        if (this.sealed || connFailed) return
        if (msg.truncated || msg.budgetDropped) {
          if (!msg.budgetDropped && this.opts.injectedScriptSha256Allowlist?.has(msg.sha256)) {
            this.countMethod('_playwright.injectedScript')
            return
          }
          const headText = msg.head.length ? msg.head.toString('utf8') : (msg.sniff ?? '')
          const methodMatch = /"method"\s*:\s*"([^"]{1,64})"/.exec(headText)
          const sessionMatch = /"sessionId"\s*:\s*"([^"]{1,128})"/.exec(headText)
          const rawInner = methodMatch?.[1]
          let safeInner: string | undefined
          if (rawInner) {
            this.countMethod(rawInner)
            const si = scrubCdpIdent(rawInner, MAX_METHOD_NAME_BYTES)
            safeInner = si && SAFE_CDP_IDENT_RE.test(si) && !isDataLikeKey(si) ? si : '_unknown'
          }
          const sid = scrubCdpSessionId(sessionMatch?.[1])
          const live = forceLive || this.opts.isLive()
          this.appendRecord({
            t: new Date().toISOString(),
            conn,
            ...(sid && { cdpSession: sid }),
            method: '_tap.oversized',
            severity: 'high',
            ...(live && { live: true as const }),
            summary: {
              bytes: msg.totalBytes,
              ...(msg.budgetDropped && { reason: 'budget' }),
              ...(safeInner && { innerMethod: safeInner }),
              sha256: msg.sha256.slice(0, 16),
            },
          })
          return
        }
        const text = msg.head.toString('utf8')
        this.handleCommand(
          conn,
          text,
          undefined,
          0,
          msg.sha256,
          msg.totalBytes,
          forceLive,
          driveBuf ? (m, p) => driveBuf.onEvent(m, p) : undefined,
        )
      },
      reason => failConn(reason),
      this.getParserCharger(),
    )

    return {
      feed: (chunk: Buffer) => {
        if (connFailed || this.sealed) return
        try {
          parser.feed(chunk)
        } catch (e: any) {
          failConn(e?.message ?? 'tap exception')
        }
      },
      close: () => {
        parser.close()
        driveBuf?.flush()
        for (const [key, slot] of [...this.slots.entries()]) {
          if (slot.conn === conn) this.flushSlot(key)
        }
      },
    }
  }

  seal(): { cdpCursor: number; droppedCdp: number } {
    if (this.sealed) return { cdpCursor: this.cursor, droppedCdp: this.droppedCdp }
    for (const key of [...this.slots.keys()]) this.flushSlot(key)

    // Build summary strictly bounded inside summaryReserve (never exceeding maxBytes!)
    const summary: CdpTapSummary = {
      n: this.cursor + 1,
      rec: '_tap.summary',
      t: new Date().toISOString(),
      methodCounts: Object.fromEntries(Object.entries(this.methodCounts)),
      depthLimited: this.depthLimited,
      droppedCdp: this.droppedCdp,
      droppedHighSeverity: this.droppedHighSeverity,
    }
    let size = Buffer.byteLength(JSON.stringify(summary), 'utf8')
    if (this.bytes + size > this.maxBytes) {
      // Collapse methodCounts into total if tight test cap
      const total = Object.values(summary.methodCounts).reduce((a, b) => a + b, 0)
      summary.methodCounts = { _total: total }
      size = Buffer.byteLength(JSON.stringify(summary), 'utf8')
    }
    if (this.bytes + size <= this.maxBytes || this.entries.length === 0) {
      summary.n = ++this.cursor
      this.entries.push(scrubDeep(summary, this.opts.vault))
      this.bytes += size
    }
    this.sealed = true
    return { cdpCursor: this.cursor, droppedCdp: this.droppedCdp }
  }

  getPage(after: number, limit = 500) {
    return page(this.entries, e => e.n, this.cursor, after, Math.min(500, Math.max(1, limit)), MAX_PAGE_BYTES, this.droppedCdp)
  }

  clear(): void {
    for (const slot of this.slots.values()) clearTimeout(slot.timer)
    this.slots.clear()
    this.lastKeyByConnSession.clear()
    this.entries = []
    this.bytes = 0
  }
}

// Passive uncompressed /view/drive observer for SecretVault ONLY (per-connection edit buffer, never logged).
export function createDriveVaultTap(vault: SecretVault, charger?: BudgetCharger, onError?: (reason: string) => void): { feed: (chunk: Buffer) => void; close: () => void } {
  let failed = false
  const driveBuf = vault.createDriveBuffer()
  const failTap = (reason: string) => {
    if (failed) return
    failed = true
    driveBuf.clear()
    onError?.(reason)
  }
  const parser = new WsFrameParser(
    msg => {
      if (failed || msg.truncated || msg.budgetDropped) return
      let parsed: any
      try {
        parsed = JSON.parse(msg.head.toString('utf8'))
      } catch {
        return
      }
      if (!parsed || typeof parsed !== 'object' || typeof parsed.method !== 'string') return
      driveBuf.onEvent(parsed.method, parsed.params)
    },
    reason => failTap(reason),
    charger,
  )
  return {
    feed: (chunk: Buffer) => {
      if (failed) return
      try {
        parser.feed(chunk)
      } catch (e: any) {
        failTap(e?.message ?? 'tap exception')
      }
    },
    close: () => {
      parser.close()
      try {
        driveBuf.flush()
      } catch {}
    },
  }
}
