import crypto from 'node:crypto'
import { page } from './page.ts'
import {
  isDataLikeKey,
  isSensitiveValue,
  sanitizeUrl,
  scanJsonDuplicateKeys,
  scrubDeep,
  scrubStructuralKey,
  scrubText,
  truncateUtf8HeadTail,
  type SecretVault,
} from './redact.ts'

const MAX_MSG_HEAD = 65_536
const MAX_DRIVE_MSG = 4_096
const MAX_CONTROL_LEN = 125
const MAX_FRAME_LEN = 256 * 1024 * 1024
const MAX_METHOD_NAMES = 256
const MAX_METHOD_NAME_BYTES = 64
const DEFAULT_MAX_ENTRIES = 4_000
const MAX_OVERFLOW_HIGH_SEV = 64
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
  totalBytes: number
  truncated: boolean
}

export class WsFrameParser {
  private failed = false
  private state: 'hdr2' | 'len16' | 'len64' | 'mask' | 'payload' = 'hdr2'
  private hdrBuf = Buffer.alloc(8)
  private hdrPos = 0
  private hdrNeed = 2

  private frameFin = false
  private frameOpcode = 0
  private frameIsControl = false
  private framePayloadRem = 0
  private maskKey = Buffer.alloc(4)
  private maskPos = 0

  private msgActive = false
  private msgOpcode = 0
  private msgHead = Buffer.alloc(0)
  private msgHeadLen = 0
  private msgTotalBytes = 0

  private maxHead: number
  private onMessage: (msg: ParsedWsMessage) => void
  private onError: (reason: string) => void

  constructor(onMessage: (msg: ParsedWsMessage) => void, onError: (reason: string) => void, maxHead = MAX_MSG_HEAD) {
    this.onMessage = onMessage
    this.onError = onError
    this.maxHead = maxHead
  }

  private resetMsg() {
    this.msgActive = false
    this.msgHead = Buffer.alloc(0)
    this.msgHeadLen = 0
    this.msgTotalBytes = 0
  }

  private fail(reason: string) {
    if (this.failed) return
    this.failed = true
    this.resetMsg()
    this.onError(reason)
  }

  close() {
    this.resetMsg()
  }

  private startPayload() {
    if (this.frameIsControl) {
      this.state = this.framePayloadRem === 0 ? 'hdr2' : 'payload'
      if (this.state === 'hdr2') { this.hdrPos = 0; this.hdrNeed = 2 }
      return
    }
    if (this.frameOpcode === 0x0) {
      if (!this.msgActive) return this.fail('unexpected continuation frame')
    } else {
      if (this.msgActive) return this.fail('new data frame while fragmented message open')
      this.msgActive = true
      this.msgOpcode = this.frameOpcode
      this.msgHead = Buffer.alloc(0)
      this.msgHeadLen = 0
      this.msgTotalBytes = 0
    }
    if (this.framePayloadRem === 0) this.finishFrame()
    else this.state = 'payload'
  }

  private finishFrame() {
    if (!this.frameIsControl && this.frameFin) {
      const msg: ParsedWsMessage = {
        opcode: this.msgOpcode,
        head: this.msgHead.subarray(0, this.msgHeadLen),
        totalBytes: this.msgTotalBytes,
        truncated: this.msgTotalBytes > this.maxHead,
      }
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
    if (this.failed || !chunk.length) return
    let off = 0
    const len = chunk.length

    while (off < len && !this.failed) {
      if (this.state !== 'payload') {
        const take = Math.min(this.hdrNeed - this.hdrPos, len - off)
        chunk.copy(this.hdrBuf, this.hdrPos, off, off + take)
        this.hdrPos += take
        off += take
        if (this.hdrPos < this.hdrNeed) return

        if (this.state === 'hdr2') {
          const b0 = this.hdrBuf[0], b1 = this.hdrBuf[1]
          this.frameFin = (b0 & 0x80) !== 0
          const rsv = b0 & 0x70
          this.frameOpcode = b0 & 0x0f
          const masked = (b1 & 0x80) !== 0
          const len7 = b1 & 0x7f
          if (rsv !== 0) return this.fail(`non-zero RSV bits: 0x${rsv.toString(16)}`)
          if (!masked) return this.fail('unmasked client frame')
          this.frameIsControl = this.frameOpcode >= 0x8
          if (this.frameOpcode > 0xa || (this.frameOpcode >= 0x3 && this.frameOpcode <= 0x7)) return this.fail(`invalid opcode: ${this.frameOpcode}`)
          if (this.frameIsControl && !this.frameFin) return this.fail('fragmented control frame')
          if (len7 < 126) {
            if (this.frameIsControl && len7 > MAX_CONTROL_LEN) return this.fail(`control frame too large: ${len7}`)
            this.framePayloadRem = len7
            this.state = 'mask'; this.hdrPos = 0; this.hdrNeed = 4
          } else if (len7 === 126) {
            if (this.frameIsControl) return this.fail('control frame too large')
            this.state = 'len16'; this.hdrPos = 0; this.hdrNeed = 2
          } else {
            if (this.frameIsControl) return this.fail('control frame too large')
            this.state = 'len64'; this.hdrPos = 0; this.hdrNeed = 8
          }
        } else if (this.state === 'len16') {
          this.framePayloadRem = this.hdrBuf.readUInt16BE(0)
          this.state = 'mask'; this.hdrPos = 0; this.hdrNeed = 4
        } else if (this.state === 'len64') {
          const big = this.hdrBuf.readBigUInt64BE(0)
          if ((this.hdrBuf[0] & 0x80) !== 0 || big > BigInt(MAX_FRAME_LEN)) return this.fail('64-bit frame length overflow')
          this.framePayloadRem = Number(big)
          this.state = 'mask'; this.hdrPos = 0; this.hdrNeed = 4
        } else {
          this.hdrBuf.copy(this.maskKey, 0, 0, 4)
          this.maskPos = 0
          this.startPayload()
        }
      } else {
        const avail = Math.min(this.framePayloadRem, len - off)
        if (!this.frameIsControl) {
          const headRoom = this.maxHead - this.msgHeadLen
          const unmaskLen = Math.min(avail, headRoom)
          if (unmaskLen > 0) {
            if (this.msgHeadLen + unmaskLen > this.msgHead.length) {
              const nextCap = Math.min(this.maxHead, Math.max(4096, this.msgHead.length * 2, this.msgHeadLen + unmaskLen))
              const next = Buffer.allocUnsafe(nextCap)
              if (this.msgHeadLen > 0) this.msgHead.copy(next, 0, 0, this.msgHeadLen)
              this.msgHead = next
            }
            for (let i = 0; i < unmaskLen; i++) {
              this.msgHead[this.msgHeadLen + i] = chunk[off + i] ^ this.maskKey[(this.maskPos + i) & 3]
            }
            this.msgHeadLen += unmaskLen
          }
          this.msgTotalBytes += avail
        }
        off += avail
        this.framePayloadRem -= avail
        this.maskPos = (this.maskPos + avail) & 3
        if (this.framePayloadRem === 0) this.finishFrame()
      }
    }
  }
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

type PendingSlot = {
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

export type CdpTapOptions = {
  vault?: SecretVault
  isLive: () => boolean
  coalesceMs?: number
  maxEntries?: number
  onFileUpload?: () => void
}

export class CdpSessionTap {
  entries: CdpLogRecord[] = []
  private cursor = 0
  private connSeq = 0
  private methodCounts = new Map<string, number>()
  private depthLimited = 0
  private droppedCdp = 0
  private droppedHighSeverity = 0
  private overflowHighSevUsed = 0
  private pendingByConn = new Map<number, PendingSlot>()
  private sealed = false
  private opts: CdpTapOptions
  private coalesceMs: number
  private maxEntries: number

  constructor(opts: CdpTapOptions) {
    this.opts = opts
    this.coalesceMs = opts.coalesceMs ?? 2_000
    this.maxEntries = opts.maxEntries ?? DEFAULT_MAX_ENTRIES
  }

  get currentCursor(): number {
    return this.cursor
  }

  get dropped(): number {
    return this.droppedCdp
  }

  private countMethod(rawMethod: string) {
    const valid = SAFE_CDP_IDENT_RE.test(rawMethod) && Buffer.byteLength(rawMethod, 'utf8') <= MAX_METHOD_NAME_BYTES
    const key = valid && (this.methodCounts.has(rawMethod) || this.methodCounts.size < MAX_METHOD_NAMES) ? rawMethod : '_unknown_other'
    this.methodCounts.set(key, (this.methodCounts.get(key) ?? 0) + 1)
  }

  private appendRecord(rec: Omit<CdpEntry, 'n'>): CdpEntry | null {
    if (this.sealed) return null
    const isHigh = rec.severity === 'high'
    if (this.entries.length >= this.maxEntries) {
      if (isHigh && this.overflowHighSevUsed < MAX_OVERFLOW_HIGH_SEV) {
        this.overflowHighSevUsed++
      } else {
        this.droppedCdp++
        if (isHigh) this.droppedHighSeverity++
        return null
      }
    }
    const entry = scrubDeep({ n: ++this.cursor, ...rec }, this.opts.vault)
    this.entries.push(entry)
    return entry
  }

  private flushConn(conn: number) {
    const slot = this.pendingByConn.get(conn)
    if (!slot) return
    clearTimeout(slot.timer)
    this.pendingByConn.delete(conn)
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
    const key = `${cdpSession ?? ''}|${method}|${severity ?? ''}|${ambiguous ? 1 : 0}|${live ? 1 : 0}|${summary ? JSON.stringify(summary) : ''}`

    const existing = this.pendingByConn.get(conn)
    if (existing) {
      if (existing.key === key) {
        existing.count++
        existing.lastT = now
        return
      }
      this.flushConn(conn)
    }

    const timer = setTimeout(() => this.flushConn(conn), this.coalesceMs)
    timer.unref()
    this.pendingByConn.set(conn, {
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
  }

  private handleCommand(
    conn: number,
    rawText: string,
    cdpSessionFallback: string | undefined,
    depth: number,
    rawTotalBytes?: number,
    forceLive = false,
    onParsed?: (method: string, params: Record<string, unknown>) => void,
  ) {
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
    const ambiguous = scanJsonDuplicateKeys(rawText)

    this.countMethod(rawMethod)
    const safeMethod = scrubCdpIdent(rawMethod, MAX_METHOD_NAME_BYTES) ?? '_unknown'

    if (rawMethod === 'Target.sendMessageToTarget' && typeof params.message === 'string') {
      if (depth >= 2) {
        this.depthLimited++
        this.enqueue(conn, cdpSession, safeMethod, 'high', ambiguous, { depthLimited: true }, forceLive)
        return
      }
      const innerSession = typeof params.sessionId === 'string' ? params.sessionId : cdpSession
      this.handleCommand(conn, params.message, innerSession, depth + 1, undefined, forceLive, onParsed)
      return
    }

    let severity: 'high' | undefined = ambiguous ? 'high' : undefined
    let summary: Record<string, unknown> | undefined
    let capture = false

    if (rawMethod === 'Runtime.callFunctionOn') {
      capture = true
      const fn = typeof params.functionDeclaration === 'string' ? params.functionDeclaration : ''
      const fnLen = Buffer.byteLength(fn, 'utf8')
      const args = Array.isArray(params.arguments) ? params.arguments : []
      summary = { fnLen, fnHash64: hash64(fn), argCount: args.length }
      if (fnLen > 16_384 || (rawTotalBytes ?? 0) > 16_384) severity = 'high'
    } else if (rawMethod === 'Runtime.evaluate' || rawMethod === 'Page.addScriptToEvaluateOnNewDocument') {
      capture = true
      const expr = typeof params.expression === 'string' ? params.expression : typeof params.source === 'string' ? params.source : ''
      const exprLen = Buffer.byteLength(expr, 'utf8')
      summary = { exprLen, exprHash64: hash64(expr) }
      if (exprLen > 16_384 || (rawTotalBytes ?? 0) > 16_384) severity = 'high'
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
      const stripped = rawUrl.trim().replace(/[\u0000-\u001f]+/g, '')
      const vault = this.opts.vault
      const rawHit = Boolean(vault && (vault.scrub(rawUrl).count > 0 || (stripped !== rawUrl && vault.scrub(stripped).count > 0)))
      let navUrl: string
      let extra: Record<string, unknown> = {}

      if (/^https?:/i.test(stripped)) {
        const parsed = URL.parse(stripped)
        const scheme = /^https:/i.test(stripped) ? 'https:' : 'http:'
        if (!parsed || (rawHit && vault!.scrub(parsed.host).count > 0)) {
          navUrl = `${scheme}//[REDACTED]`
        } else {
          navUrl = sanitizeUrl(parsed, { projection: 'semantic' }).url
        }
      } else if (/^data:/i.test(stripped)) {
        severity = 'high'
        const comma = stripped.indexOf(',')
        const meta = (comma >= 0 ? stripped.slice(5, comma) : stripped.slice(5)).split(';')[0].trim()
        const mime = !rawHit && /^[A-Za-z0-9.+-]+\/[A-Za-z0-9.+-]+$/.test(meta) ? meta.toLowerCase() : '[REDACTED]'
        navUrl = `data:${mime};len=${Buffer.byteLength(rawUrl, 'utf8')}`
      } else {
        const schemeMatch = /^([a-z][a-z0-9+.-]{0,15}):/i.exec(stripped)
        const scheme = schemeMatch ? schemeMatch[1].toLowerCase() : 'unknown'
        if (scheme === 'javascript' || scheme === 'vbscript') {
          severity = 'high'
          navUrl = rawHit ? '[REDACTED]' : `${scheme}:[REDACTED]`
          extra = { exprLen: Buffer.byteLength(rawUrl, 'utf8'), exprHash64: hash64(rawUrl) }
        } else if (/^about:(?:blank|srcdoc)$/i.test(stripped)) {
          navUrl = rawHit ? '[REDACTED]' : stripped.toLowerCase()
        } else {
          navUrl = rawHit ? '[REDACTED]' : `${scheme}:[REDACTED]`
          extra = { len: Buffer.byteLength(rawUrl, 'utf8') }
        }
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
      summary = { len: typeof params.text === 'string' ? params.text.length : 0 }
    } else if (rawMethod === 'Input.dispatchKeyEvent') {
      if (params.type === 'char') {
        capture = true
        summary = { len: typeof params.text === 'string' ? params.text.length : 0 }
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
      summary = { key: truncateUtf8HeadTail(typeof params.key === 'string' ? scrubStructuralKey(params.key).key : '', 64) }
    } else if (rawMethod === 'Storage.setStorageItems') {
      capture = true
      const items = Array.isArray(params.items)
        ? params.items.slice(0, 32).map(it => truncateUtf8HeadTail(scrubStructuralKey(typeof (it as any)?.key === 'string' ? (it as any).key : '').key, 64))
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
        if (msg.truncated) {
          const headText = msg.head.toString('utf8')
          const rawInner = /"method"\s*:\s*"([^"]{1,64})"/.exec(headText)?.[1]
          let safeInner: string | undefined
          if (rawInner) {
            this.countMethod(rawInner)
            const si = scrubCdpIdent(rawInner, MAX_METHOD_NAME_BYTES)
            safeInner = si && SAFE_CDP_IDENT_RE.test(si) && !isDataLikeKey(si) ? si : '_unknown'
          }
          const sid = scrubCdpSessionId(/"sessionId"\s*:\s*"([^"]{1,128})"/.exec(headText)?.[1])
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
              ...(safeInner && { innerMethod: safeInner }),
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
          msg.totalBytes,
          forceLive,
          driveBuf ? (m, p) => driveBuf.onEvent(m, p) : undefined,
        )
      },
      reason => failConn(reason),
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
        this.flushConn(conn)
      },
    }
  }

  seal(): { cdpCursor: number; droppedCdp: number } {
    if (this.sealed) return { cdpCursor: this.cursor, droppedCdp: this.droppedCdp }
    for (const conn of [...this.pendingByConn.keys()]) this.flushConn(conn)
    const summary: CdpTapSummary = {
      n: ++this.cursor,
      rec: '_tap.summary',
      t: new Date().toISOString(),
      methodCounts: Object.fromEntries(this.methodCounts),
      depthLimited: this.depthLimited,
      droppedCdp: this.droppedCdp,
      droppedHighSeverity: this.droppedHighSeverity,
    }
    this.entries.push(scrubDeep(summary, this.opts.vault))
    this.sealed = true
    return { cdpCursor: this.cursor, droppedCdp: this.droppedCdp }
  }

  getPage(after: number, limit = 500) {
    return page(this.entries, e => e.n, this.cursor, after, Math.min(500, Math.max(1, limit)), MAX_PAGE_BYTES, this.droppedCdp)
  }

  clear(): void {
    for (const slot of this.pendingByConn.values()) clearTimeout(slot.timer)
    this.pendingByConn.clear()
    this.entries = []
  }
}

export function createDriveVaultTap(vault: SecretVault, onError?: (reason: string) => void): { feed: (chunk: Buffer) => void; close: () => void } {
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
      if (failed || msg.truncated) return
      let parsed: any
      try { parsed = JSON.parse(msg.head.toString('utf8')) } catch { return }
      if (!parsed || typeof parsed !== 'object' || typeof parsed.method !== 'string') return
      driveBuf.onEvent(parsed.method, parsed.params)
    },
    reason => failTap(reason),
    MAX_DRIVE_MSG,
  )
  return {
    feed: (chunk: Buffer) => {
      if (failed) return
      try { parser.feed(chunk) } catch (e: any) { failTap(e?.message ?? 'tap exception') }
    },
    close: () => {
      parser.close()
      driveBuf.flush()
    },
  }
}
