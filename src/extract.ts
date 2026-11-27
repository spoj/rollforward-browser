import zlib from 'node:zlib'
import {
  buildBodyShape,
  buildFormBodyShape,
  isDataLikeKey,
  isSensitiveValue,
  parseJsonSafe,
  redactFormBody,
  redactJsonValue,
  redactPlainText,
  scrubStructuralKey,
  scrubText,
  truncateUtf8HeadTail,
  type ProjectionMode,
  type SecretVault,
} from './redact.ts'

export const EXTRACTOR_V = 1
export const MAX_PREFIX_BYTES = 65_536
export const MAX_SAMPLE_BODY_BYTES = 4_096

export type BodyOmittedReason =
  | 'live'
  | 'auth-url'
  | 'binary'
  | 'budget'
  | 'decompress-err'
  | 'timeout'
  | 'policy-profile'

export type SemanticAction = {
  family: 'e1-ais' | 'sharepoint' | 'graphql' | 'soap' | 'rest' | 'api' | 'upgrade'
  op: string
  resource?: string
  details?: Record<string, unknown>
  coverage: 'complete' | 'partial' | 'opaque-batch' | 'persisted-query-unknown' | 'unknown'
}

export type Completeness = {
  transport: 'complete' | 'truncated' | 'not-read'
  decode: 'complete' | 'truncated' | 'error' | 'none'
  extract: 'complete' | 'partial' | 'opaque' | 'none'
  reasons?: string[]
}

export type GraphqlOp = 'query' | 'mutation' | 'subscription' | 'mixed' | 'persisted'

export type DecompressResult = {
  ok: boolean
  buf: Buffer
  decodeComplete: boolean
  decode: 'complete' | 'truncated' | 'error' | 'none'
  truncated: boolean
  reason?: string
  budgetExceeded?: boolean
  chargedBytes?: number
}

export type DecodeBudgetCharger = {
  tryAcquire: (bytes: number) => boolean
  release: (bytes: number) => void
}

const SUPPORTED_ENCODINGS = new Set(['gzip', 'x-gzip', 'deflate', 'br', 'zstd'])

function decompressSingleLayer(
  input: Buffer,
  encoding: string,
  inputComplete: boolean,
  maxBytes: number,
  maxMs: number,
  charger?: DecodeBudgetCharger,
  rawDeflateFallback = false,
): Promise<DecompressResult> {
  return new Promise(resolve => {
    let stream: zlib.Gunzip | zlib.Inflate | zlib.InflateRaw | zlib.BrotliDecompress | zlib.ZstdDecompress
    try {
      // Strict codec EOF when transport is complete (catches truncated trailers!); partial flush ONLY when prefix is already known truncated.
      if (encoding === 'gzip' || encoding === 'x-gzip') {
        stream = inputComplete ? zlib.createGunzip() : zlib.createGunzip({ finishFlush: zlib.constants.Z_SYNC_FLUSH })
      } else if (encoding === 'deflate') {
        if (rawDeflateFallback) {
          stream = inputComplete ? zlib.createInflateRaw() : zlib.createInflateRaw({ finishFlush: zlib.constants.Z_SYNC_FLUSH })
        } else {
          stream = inputComplete ? zlib.createInflate() : zlib.createInflate({ finishFlush: zlib.constants.Z_SYNC_FLUSH })
        }
      } else if (encoding === 'br') {
        stream = inputComplete ? zlib.createBrotliDecompress() : zlib.createBrotliDecompress({ finishFlush: zlib.constants.BROTLI_OPERATION_FLUSH })
      } else if (encoding === 'zstd') {
        stream = zlib.createZstdDecompress()
      } else {
        resolve({ ok: false, buf: Buffer.alloc(0), decodeComplete: false, decode: 'error', truncated: false, reason: 'unsupported-encoding' })
        return
      }
    } catch {
      resolve({ ok: false, buf: Buffer.alloc(0), decodeComplete: false, decode: 'error', truncated: false, reason: 'codec-init-error' })
      return
    }

    const chunks: Buffer[] = []
    let outBytes = 0
    let charged = 0
    let done = false
    const start = performance.now()

    const releaseAll = () => {
      if (charged > 0 && charger) {
        charger.release(charged)
        charged = 0
      }
    }

    const timer = setTimeout(() => {
      if (done) return
      done = true
      stream.destroy()
      resolve({
        ok: true,
        buf: Buffer.concat(chunks).subarray(0, maxBytes),
        decodeComplete: false,
        decode: 'truncated',
        truncated: true,
        reason: 'decompress-cpu-limit',
        chargedBytes: charged,
      })
    }, maxMs)
    timer.unref?.()

    const finish = (res: DecompressResult) => {
      if (done) return
      done = true
      clearTimeout(timer)
      resolve(res)
    }

    stream.on('data', (c: Buffer) => {
      if (done) return
      if (performance.now() - start > maxMs) {
        stream.destroy()
        finish({
          ok: true,
          buf: Buffer.concat(chunks).subarray(0, maxBytes),
          decodeComplete: false,
          decode: 'truncated',
          truncated: true,
          reason: 'decompress-cpu-limit',
          chargedBytes: charged,
        })
        return
      }
      const need = Math.min(c.length, maxBytes - outBytes)
      if (need > 0 && charger && !charger.tryAcquire(need)) {
        stream.destroy()
        chunks.length = 0
        releaseAll()
        finish({
          ok: false,
          buf: Buffer.alloc(0),
          decodeComplete: false,
          decode: 'error',
          truncated: true,
          reason: 'inflight-budget',
          budgetExceeded: true,
          chargedBytes: 0,
        })
        return
      }
      if (need > 0) {
        if (charger) charged += need
        chunks.push(need < c.length ? Buffer.from(c.subarray(0, need)) : c)
        outBytes += need
      }
      if (outBytes >= maxBytes) {
        stream.destroy()
        finish({
          ok: true,
          buf: Buffer.concat(chunks),
          decodeComplete: false,
          decode: 'truncated',
          truncated: true,
          reason: '>64KiB-decoded',
          chargedBytes: charged,
        })
      }
    })

    stream.on('end', () => {
      const buf = Buffer.concat(chunks)
      chunks.length = 0
      if (!inputComplete) {
        finish({ ok: true, buf, decodeComplete: false, decode: 'truncated', truncated: true, reason: '>64KiB', chargedBytes: charged })
      } else {
        finish({ ok: true, buf, decodeComplete: true, decode: 'complete', truncated: false, chargedBytes: charged })
      }
    })

    stream.on('error', () => {
      const buf = Buffer.concat(chunks)
      chunks.length = 0
      if (!inputComplete) {
        finish({ ok: true, buf, decodeComplete: false, decode: 'truncated', truncated: true, reason: '>64KiB', chargedBytes: charged })
        return
      }
      releaseAll()
      if (encoding === 'deflate' && !rawDeflateFallback) {
        clearTimeout(timer)
        done = true
        void decompressSingleLayer(input, encoding, inputComplete, maxBytes, maxMs, charger, true).then(resolve)
        return
      }
      finish({ ok: false, buf: Buffer.alloc(0), decodeComplete: false, decode: 'error', truncated: false, reason: 'decompress-err', chargedBytes: 0 })
    })

    const SLICE = 4096
    let offset = 0
    const pump = () => {
      while (!done && offset < input.length) {
        const end = Math.min(offset + SLICE, input.length)
        const slice = input.subarray(offset, end)
        offset = end
        if (!stream.write(slice)) {
          stream.once('drain', pump)
          return
        }
      }
      if (!done) stream.end()
    }
    pump()
  })
}

export async function decompressPrefix(
  rawBuf: Buffer,
  contentEncoding: string | undefined,
  bodyComplete: boolean,
  maxBytes = MAX_PREFIX_BYTES,
  maxMs = 50,
  charger?: DecodeBudgetCharger,
): Promise<DecompressResult> {
  if (rawBuf.length === 0) {
    return { ok: true, buf: rawBuf, decodeComplete: bodyComplete, decode: 'none', truncated: !bodyComplete, chargedBytes: 0 }
  }
  const encodings = (contentEncoding ?? '')
    .split(',')
    .map(s => s.trim().toLowerCase())
    .filter(s => s && s !== 'identity')
  if (encodings.length === 0) {
    return {
      ok: true,
      buf: rawBuf.subarray(0, maxBytes),
      decodeComplete: bodyComplete && rawBuf.length <= maxBytes,
      decode: bodyComplete && rawBuf.length <= maxBytes ? 'complete' : 'truncated',
      truncated: !bodyComplete || rawBuf.length > maxBytes,
      chargedBytes: 0,
    }
  }
  if (encodings.length > 2 || encodings.some(e => !SUPPORTED_ENCODINGS.has(e))) {
    return {
      ok: false,
      buf: Buffer.alloc(0),
      decodeComplete: false,
      decode: 'error',
      truncated: false,
      reason: 'unsupported-encoding',
      chargedBytes: 0,
    }
  }
  let curBuf = rawBuf
  let curComplete = bodyComplete
  let curCharged = 0
  let anyTruncated = !bodyComplete
  for (let i = encodings.length - 1; i >= 0; i--) {
    const res = await decompressSingleLayer(curBuf, encodings[i], curComplete, maxBytes, maxMs, charger)
    if (curCharged > 0 && charger) {
      charger.release(curCharged)
      curCharged = 0
    }
    if (!res.ok) return res
    curBuf = res.buf
    curComplete = res.decodeComplete
    curCharged = res.chargedBytes ?? 0
    if (res.truncated) anyTruncated = true
  }
  return {
    ok: true,
    buf: curBuf,
    decodeComplete: curComplete && !anyTruncated,
    decode: curComplete && !anyTruncated ? 'complete' : 'truncated',
    truncated: anyTruncated,
    chargedBytes: curCharged,
  }
}

export function normalizeContentType(header: string | undefined): string | undefined {
  if (!header) return undefined
  const essence = header.split(';')[0].trim().toLowerCase()
  return essence || undefined
}

export function isBinaryContentType(reqType: string | undefined): boolean {
  if (!reqType) return false
  if (reqType === 'multipart/form-data') return true
  if (reqType.startsWith('image/') || reqType.startsWith('video/') || reqType.startsWith('audio/') || reqType.startsWith('font/')) return true
  if (
    reqType === 'application/octet-stream' ||
    reqType === 'application/pdf' ||
    reqType === 'application/zip' ||
    reqType === 'application/gzip' ||
    reqType === 'application/wasm'
  ) {
    return true
  }
  return false
}

export function hasBinaryMagic(buf: Buffer): boolean {
  if (!buf.length) return false
  if (buf.length >= 4) {
    if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return true
    if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return true
    if (buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x38) return true
    if (buf[0] === 0x25 && buf[1] === 0x50 && buf[2] === 0x44 && buf[3] === 0x46) return true
    if (buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) return true
    if (buf[0] === 0x77 && buf[1] === 0x4f && buf[2] === 0x46 && (buf[3] === 0x46 || buf[3] === 0x32)) return true
  }
  if (buf.includes(0x00)) return true
  return false
}

export function decodeUtf8Prefix(buf: Buffer, truncated: boolean): string | null {
  if (!buf.length) return ''
  const dec = new TextDecoder('utf-8', { fatal: true })
  const maxTrim = truncated ? Math.min(3, buf.length) : 0
  for (let trim = 0; trim <= maxTrim; trim++) {
    try {
      return dec.decode(trim ? buf.subarray(0, buf.length - trim) : buf)
    } catch {
      // retry with one fewer trailing byte if truncated mid-codepoint
    }
  }
  return null
}

// Strict token-level GraphQL document classifier.
export function classifyGraphqlQuery(
  query: string,
  operationName?: string,
): { op: GraphqlOp; opNames: string[]; opKinds: string[] } {
  type OpDef = { kind: 'query' | 'mutation' | 'subscription'; name?: string }
  const ops: OpDef[] = []
  const len = query.length
  let i = 0
  let depth = 0
  let pendingOp: 'query' | 'mutation' | 'subscription' | null = null
  let pendingName: string | undefined
  let skippingFragmentHeader = false

  const isNameStart = (c: number) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95
  const isNameCont = (c: number) => isNameStart(c) || (c >= 48 && c <= 57)

  while (i < len) {
    const ch = query[i]
    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n' || ch === ',' || ch === '\ufeff') {
      i++
      continue
    }
    if (ch === '#') {
      while (i < len && query[i] !== '\n' && query[i] !== '\r') i++
      continue
    }
    if (ch === '"') {
      if (query.startsWith('"""', i)) {
        i += 3
        while (i < len) {
          if (query[i] === '\\' && query.startsWith('"""', i + 1)) {
            i += 4
            continue
          }
          if (query.startsWith('"""', i)) {
            i += 3
            break
          }
          i++
        }
      } else {
        i++
        while (i < len) {
          if (query[i] === '\\') {
            i += 2
            continue
          }
          if (query[i] === '"') {
            i++
            break
          }
          i++
        }
      }
      continue
    }
    if (ch === '{') {
      if (depth === 0) {
        if (skippingFragmentHeader) {
          skippingFragmentHeader = false
        } else if (pendingOp) {
          ops.push({ kind: pendingOp, name: pendingName })
          pendingOp = null
          pendingName = undefined
        } else {
          ops.push({ kind: 'query', name: undefined })
        }
      }
      depth++
      i++
      continue
    }
    if (ch === '}') {
      if (depth > 0) depth--
      i++
      continue
    }
    if (ch === '(') {
      let pDepth = 1
      i++
      while (i < len && pDepth > 0) {
        const pc = query[i]
        if (pc === '"') {
          if (query.startsWith('"""', i)) {
            i += 3
            while (i < len && !query.startsWith('"""', i)) i += query[i] === '\\' ? 2 : 1
            i += 3
          } else {
            i++
            while (i < len && query[i] !== '"') i += query[i] === '\\' ? 2 : 1
            i++
          }
          continue
        }
        if (pc === '#') {
          while (i < len && query[i] !== '\n') i++
          continue
        }
        if (pc === '(') pDepth++
        else if (pc === ')') pDepth--
        i++
      }
      continue
    }
    if (ch === '@') {
      i++
      while (i < len && isNameCont(query.charCodeAt(i))) i++
      continue
    }
    const code = query.charCodeAt(i)
    if (isNameStart(code)) {
      const start = i
      i++
      while (i < len && isNameCont(query.charCodeAt(i))) i++
      if (depth === 0) {
        const word = query.slice(start, i)
        if (word === 'fragment') {
          skippingFragmentHeader = true
          pendingOp = null
          pendingName = undefined
        } else if (word === 'query' || word === 'mutation' || word === 'subscription') {
          if (!skippingFragmentHeader) {
            pendingOp = word
            pendingName = undefined
          }
        } else if (pendingOp && pendingName === undefined && !skippingFragmentHeader) {
          pendingName = word
        }
      }
      continue
    }
    i++
  }

  const opNames = ops.map(o => o.name ?? '<anonymous>')
  const opKinds = ops.map(o => o.kind)

  if (ops.length === 0) {
    return { op: 'mixed', opNames, opKinds }
  }
  if (operationName) {
    const matches = ops.filter(o => o.name === operationName)
    if (matches.length !== 1) return { op: 'mixed', opNames, opKinds }
    return { op: matches[0].kind, opNames, opKinds }
  }
  if (ops.length === 1) {
    return { op: ops[0].kind, opNames, opKinds }
  }
  return { op: 'mixed', opNames, opKinds }
}

export function extractSoapBodyRoot(xml: string): string | undefined {
  const clean = xml.replace(/<!--[\s\S]*?-->/g, '').replace(/<\?[\s\S]*?\?>/g, '')
  const bodyMatch = /<(?:[A-Za-z_][\w.-]*:)?Body(?:\s[^>]*)?>([\s\S]*)/i.exec(clean)
  if (!bodyMatch) return undefined
  const inside = bodyMatch[1]
  const childMatch = /<([A-Za-z_][\w.-]*(?::[A-Za-z_][\w.-]*)?)(?=[\s/>])/.exec(inside)
  return childMatch?.[1]
}

export type ExtractInput = {
  url: URL
  sanitizedPath: string
  method: string
  effectiveMethod: string
  kind: 'http' | 'upgrade'
  hdr?: Record<string, string>
  rawHeaders: Record<string, string | string[] | undefined>
  reqType?: string
  decodedBuf?: Buffer
  decodeResult?: DecompressResult
  bodyComplete: boolean
  transport: 'complete' | 'truncated' | 'not-read'
  transportReasons?: string[]
  isWrite: boolean
  isAuth: boolean
  isLive: boolean
  projection: ProjectionMode
  vault?: SecretVault
  sampleBudgetOk?: boolean
}

export type ExtractOutput = {
  actions: SemanticAction[]
  bodyShape?: Record<string, string>
  graphqlOp?: GraphqlOp
  dupKeys?: true
  completeness: Completeness
  decodeComplete: boolean
  reqBody?: string
  reqTrunc?: true
  reqOmitted?: BodyOmittedReason
  vaultRedactions: number
  parsedBody?: unknown
  rawBodyText?: string
}

const E1_ENDPOINTS = new Set(['formservice', 'appstack', 'dataservice', 'orchestrator', 'file', 'tokenrequest', 'discover', 'defaultconfig'])
const STRUCT_IDENT_RE = /^[A-Za-z][A-Za-z0-9_.-]{0,47}$/
const E1_CONTROL_ID_RE = /^[A-Za-z0-9_.-]{1,32}$/
const GQL_IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]{0,47}$/

function validateStructuralIdent(
  val: unknown,
  pattern: RegExp,
  vault?: SecretVault,
  allowNumeric = false,
): { value?: string; vaultRedactions: number } {
  if (typeof val !== 'string' || !val) return { vaultRedactions: 0 }
  if (vault) {
    const sv = vault.scrub(val)
    if (sv.count > 0) return { vaultRedactions: sv.count }
  }
  if (!pattern.test(val)) return { vaultRedactions: 0 }
  if (isSensitiveValue(val)) return { vaultRedactions: 0 }
  if (!allowNumeric && isDataLikeKey(val)) return { vaultRedactions: 0 }
  return { value: val, vaultRedactions: 0 }
}

export function extractSemantic(input: ExtractInput): ExtractOutput {
  const reasons: string[] = [...(input.transportReasons ?? [])]
  let vaultRedactions = 0

  if (input.kind === 'upgrade') {
    return {
      actions: [{ family: 'upgrade', op: 'upgrade:websocket', resource: input.sanitizedPath, coverage: 'complete' }],
      completeness: { transport: 'not-read', decode: 'none', extract: 'complete', ...(reasons.length && { reasons }) },
      decodeComplete: true,
      vaultRedactions: 0,
    }
  }

  try {
    const rawBuf = input.decodedBuf ?? Buffer.alloc(0)
    const decodeRes = input.decodeResult
    const decodeStatus: Completeness['decode'] = decodeRes?.decode ?? (rawBuf.length ? (input.bodyComplete ? 'complete' : 'truncated') : 'none')
    const decodeComplete = decodeRes ? decodeRes.decodeComplete : input.bodyComplete

    if (decodeRes?.reason && !reasons.includes(decodeRes.reason)) reasons.push(decodeRes.reason)
    if (input.isAuth && !reasons.includes('auth-url')) reasons.push('auth-url')
    if (input.isLive && !reasons.includes('live')) reasons.push('live')

    if (decodeRes && !decodeRes.ok) {
      const actions: SemanticAction[] = input.isWrite
        ? [{ family: 'rest', op: `rest:${input.effectiveMethod}`, resource: input.sanitizedPath, coverage: 'unknown' }]
        : []
      return {
        actions,
        completeness: { transport: input.transport, decode: 'error', extract: 'none', ...(reasons.length && { reasons }) },
        decodeComplete: false,
        reqOmitted: input.isLive ? 'live' : input.isAuth ? 'auth-url' : 'decompress-err',
        vaultRedactions,
      }
    }

    const hasBody = rawBuf.length > 0
    let isBinary = false
    let decodedText: string | undefined
    if (hasBody) {
      if (isBinaryContentType(input.reqType) || hasBinaryMagic(rawBuf)) {
        isBinary = true
        if (input.reqType === 'multipart/form-data') reasons.push('multipart')
        else reasons.push('binary')
      } else {
        const text = decodeUtf8Prefix(rawBuf, !decodeComplete || !input.bodyComplete)
        if (text === null) {
          isBinary = true
          reasons.push('invalid-utf8')
        } else {
          decodedText = text
        }
      }
    }

    let parsedJson: unknown
    let isJson = false
    let dupKeys = false
    let structuredJsonParseFailed = false
    if (decodedText !== undefined) {
      const trimmed = decodedText.trimStart()
      const looksJson = input.reqType === 'application/json' || Boolean(input.reqType?.endsWith('+json')) || trimmed.startsWith('{') || trimmed.startsWith('[')
      const parsed = parseJsonSafe(decodedText)
      if (parsed.ok) {
        isJson = true
        parsedJson = parsed.value
        dupKeys = parsed.dupKeys
        if (dupKeys) reasons.push('dupKeys')
      } else if (looksJson) {
        structuredJsonParseFailed = true
        reasons.push('json-parse-failed')
      }
    }

    let bodyShape: Record<string, string> | undefined
    if (!input.isLive && hasBody && !isBinary) {
      if (isJson && parsedJson !== null && typeof parsedJson === 'object') {
        const bs = buildBodyShape(parsedJson, input.vault)
        bodyShape = bs.shape
        vaultRedactions += bs.vaultRedactions
      } else if (decodedText !== undefined && input.reqType === 'application/x-www-form-urlencoded') {
        const bs = buildFormBodyShape(decodedText, input.vault)
        bodyShape = bs.shape
        vaultRedactions += bs.vaultRedactions
      }
    }

    const fullyIntact = input.bodyComplete && decodeComplete && !dupKeys
    const defaultCov: SemanticAction['coverage'] = fullyIntact ? 'complete' : 'partial'
    const lowerPath = input.url.pathname.toLowerCase()
    const actions: SemanticAction[] = []
    let graphqlOp: GraphqlOp | undefined
    let extractStatus: Completeness['extract'] = 'none'

    // 1. JD Edwards E1 AIS
    const obj = isJson && parsedJson && typeof parsedJson === 'object' && !Array.isArray(parsedJson)
      ? (parsedJson as Record<string, unknown>)
      : undefined
    const isE1Path = lowerPath.includes('/jderest/')
    const isE1Shape = !!obj && (
      typeof obj.formName === 'string' &&
      (Array.isArray(obj.formActions) || typeof obj.formServiceAction === 'string' || 'actionRequest' in obj || 'formRequest' in obj)
    )

    if (isE1Path || isE1Shape) {
      const m = /\/jderest\/(?:v\d+\/)?([^/;?]+)/i.exec(input.url.pathname)
      const rawEndpoint = m ? m[1].toLowerCase() : 'ais'
      const endpoint = E1_ENDPOINTS.has(rawEndpoint) ? rawEndpoint : 'ais'

      const details: Record<string, unknown> = {}
      const rawFormName = typeof obj?.formName === 'string'
        ? obj.formName
        : typeof (obj?.formRequest as any)?.formName === 'string'
          ? (obj!.formRequest as any).formName
          : typeof obj?.targetName === 'string'
            ? obj.targetName
            : undefined

      const formIdent = validateStructuralIdent(rawFormName, STRUCT_IDENT_RE, input.vault)
      vaultRedactions += formIdent.vaultRedactions
      if (formIdent.value) details.formName = formIdent.value

      const verIdent = validateStructuralIdent(obj?.version, STRUCT_IDENT_RE, input.vault)
      vaultRedactions += verIdent.vaultRedactions
      if (verIdent.value) details.version = verIdent.value

      const rawAction = typeof obj?.action === 'string' ? obj.action : typeof obj?.formServiceAction === 'string' ? obj.formServiceAction : undefined
      const actIdent = validateStructuralIdent(rawAction, /^[A-Za-z][A-Za-z0-9_-]{0,23}$/, input.vault)
      vaultRedactions += actIdent.vaultRedactions
      if (actIdent.value) details.action = actIdent.value

      const targetTypeIdent = validateStructuralIdent(obj?.targetType, STRUCT_IDENT_RE, input.vault)
      vaultRedactions += targetTypeIdent.vaultRedactions
      if (targetTypeIdent.value) details.targetType = targetTypeIdent.value

      const dsTypeIdent = validateStructuralIdent(obj?.dataServiceType, STRUCT_IDENT_RE, input.vault)
      vaultRedactions += dsTypeIdent.vaultRedactions
      if (dsTypeIdent.value) details.dataServiceType = dsTypeIdent.value

      const rawActions = Array.isArray(obj?.formActions)
        ? obj.formActions
        : Array.isArray((obj?.actionRequest as any)?.formActions)
          ? (obj!.actionRequest as any).formActions
          : Array.isArray((obj?.formRequest as any)?.formActions)
            ? (obj!.formRequest as any).formActions
            : undefined
      if (rawActions) {
        const summarized = rawActions.slice(0, 32).map(a => {
          if (!a || typeof a !== 'object') return { command: 'unknown' }
          const rec = a as Record<string, unknown>
          const item: Record<string, string> = {}
          const cmd = validateStructuralIdent(rec.command, STRUCT_IDENT_RE, input.vault)
          vaultRedactions += cmd.vaultRedactions
          if (cmd.value) item.command = cmd.value
          const cid = validateStructuralIdent(rec.controlID, E1_CONTROL_ID_RE, input.vault, true)
          vaultRedactions += cid.vaultRedactions
          if (cid.value) item.controlID = cid.value
          return item
        })
        details.formActions = summarized
        if (rawActions.length > 32) details.formActionsTruncated = true
      }

      const op = actIdent.value ? `${endpoint}:${actIdent.value}` : `${endpoint}:${input.effectiveMethod}`
      const resource = formIdent.value ?? input.sanitizedPath
      actions.push({
        family: 'e1-ais',
        op,
        resource,
        ...(Object.keys(details).length && { details }),
        coverage: defaultCov,
      })
      extractStatus = fullyIntact ? 'complete' : 'partial'
    }

    // 2. SharePoint REST API
    else if (lowerPath.includes('/_api/') || lowerPath.includes('/_vti_bin/')) {
      const apiIdx = lowerPath.indexOf('/_api/') >= 0 ? lowerPath.indexOf('/_api/') : lowerPath.indexOf('/_vti_bin/')
      const spResource = input.sanitizedPath.slice(Math.max(0, apiIdx)) || input.sanitizedPath
      if (lowerPath.includes('/$batch')) {
        actions.push({
          family: 'sharepoint',
          op: 'sharepoint:batch',
          resource: spResource,
          details: {
            hasRequestDigest: Boolean(input.rawHeaders['x-requestdigest']),
            hasIfMatch: Boolean(input.rawHeaders['if-match']),
          },
          coverage: 'opaque-batch',
        })
        extractStatus = 'opaque'
      } else {
        const details: Record<string, unknown> = {
          hasIfMatch: Boolean(input.rawHeaders['if-match']),
          hasRequestDigest: Boolean(input.rawHeaders['x-requestdigest']),
        }
        if (input.hdr?.['x-http-method']) details.override = input.hdr['x-http-method']
        const rawMetaType = (obj?.__metadata as any)?.type ?? obj?.['@odata.type']
        const metaIdent = validateStructuralIdent(rawMetaType, /^[#A-Za-z][A-Za-z0-9_.-]{0,63}$/, input.vault)
        vaultRedactions += metaIdent.vaultRedactions
        if (metaIdent.value) details.metadataType = metaIdent.value

        actions.push({
          family: 'sharepoint',
          op: `sharepoint:${input.effectiveMethod}`,
          resource: spResource,
          details,
          coverage: defaultCov,
        })
        extractStatus = fullyIntact ? 'complete' : 'partial'
      }
    }

    // 3. GraphQL (classify ALL items in bounded <=64KiB batch; cap emitted actions at 16!)
    else if (
      lowerPath.includes('/graphql') ||
      (obj && (typeof obj.query === 'string' || (obj.extensions && typeof obj.extensions === 'object' && 'persistedQuery' in (obj.extensions as Record<string, unknown>)))) ||
      (Array.isArray(parsedJson) && parsedJson.length > 0 && parsedJson.every(item => item && typeof item === 'object' && ('query' in (item as any) || 'extensions' in (item as any))))
    ) {
      const allItems = Array.isArray(parsedJson) ? parsedJson : obj ? [obj] : []
      const batchTruncated = allItems.length > 16
      if (batchTruncated) reasons.push('batch-truncated')
      const opsSeen: GraphqlOp[] = []

      for (let idx = 0; idx < allItems.length; idx++) {
        const rec = allItems[idx] as Record<string, unknown>
        const qStr = typeof rec.query === 'string' ? rec.query : undefined
        const opNameRaw = typeof rec.operationName === 'string' ? rec.operationName : undefined
        const hasPersisted = Boolean(rec.extensions && typeof rec.extensions === 'object' && 'persistedQuery' in (rec.extensions as Record<string, unknown>))

        const safeOpName = validateStructuralIdent(opNameRaw, GQL_IDENT_RE, input.vault)
        vaultRedactions += safeOpName.vaultRedactions

        let varKeys: string[] | undefined
        if (idx < 16 && rec.variables && typeof rec.variables === 'object' && !Array.isArray(rec.variables)) {
          varKeys = Object.keys(rec.variables as Record<string, unknown>).slice(0, 32).map(k => {
            const sk = scrubStructuralKey(k, input.vault)
            vaultRedactions += sk.vaultRedactions
            return sk.key
          })
        }

        if (!qStr && hasPersisted) {
          opsSeen.push('persisted')
          if (idx < 16) {
            actions.push({
              family: 'graphql',
              op: 'graphql:persisted',
              resource: safeOpName.value ?? input.sanitizedPath,
              details: { ...(varKeys && { variableKeys: varKeys }) },
              coverage: 'persisted-query-unknown',
            })
          }
          continue
        }
        if (qStr) {
          const res = classifyGraphqlQuery(qStr, opNameRaw)
          const itemOp: GraphqlOp = dupKeys ? 'mixed' : res.op
          opsSeen.push(itemOp)
          if (idx < 16) {
            const safeNames = res.opNames.slice(0, 16).map(n => {
              if (n === '<anonymous>') return n
              const v = validateStructuralIdent(n, GQL_IDENT_RE, input.vault)
              vaultRedactions += v.vaultRedactions
              return v.value ?? '<redacted>'
            })
            const resource = safeOpName.value ?? (safeNames.length === 1 && safeNames[0] !== '<anonymous>' && safeNames[0] !== '<redacted>' ? safeNames[0] : input.sanitizedPath)
            actions.push({
              family: 'graphql',
              op: `graphql:${itemOp}`,
              resource,
              details: {
                opNames: safeNames,
                opKinds: res.opKinds.slice(0, 16),
                ...(varKeys && { variableKeys: varKeys }),
              },
              coverage: !fullyIntact || itemOp === 'mixed' || batchTruncated ? 'partial' : 'complete',
            })
          }
        } else {
          opsSeen.push('mixed')
          if (idx < 16) {
            actions.push({
              family: 'graphql',
              op: 'graphql:mixed',
              resource: input.sanitizedPath,
              coverage: 'unknown',
            })
          }
        }
      }

      if (opsSeen.length === 0) {
        graphqlOp = 'mixed'
        extractStatus = 'opaque'
      } else if (opsSeen.includes('persisted')) {
        graphqlOp = opsSeen.every(o => o === 'persisted') ? 'persisted' : 'mixed'
        extractStatus = 'opaque'
      } else if (opsSeen.every(o => o === 'query') && fullyIntact && !batchTruncated) {
        graphqlOp = 'query'
        extractStatus = 'complete'
      } else if (opsSeen.every(o => o === 'mutation')) {
        graphqlOp = 'mutation'
        extractStatus = fullyIntact && !batchTruncated ? 'complete' : 'partial'
      } else if (opsSeen.every(o => o === 'subscription')) {
        graphqlOp = 'subscription'
        extractStatus = fullyIntact && !batchTruncated ? 'complete' : 'partial'
      } else {
        graphqlOp = 'mixed'
        extractStatus = 'partial'
      }
    }

    // 4. SOAP
    else if (
      input.hdr?.soapaction ||
      ((input.reqType === 'text/xml' || input.reqType === 'application/soap+xml' || input.reqType === 'application/xml') &&
        decodedText !== undefined &&
        /<(?:[A-Za-z_][\w.-]*:)?Envelope[\s>]/i.test(decodedText))
    ) {
      const claimedRaw = input.hdr?.soapaction?.replace(/^"(.*)"$/, '$1')
      const bodyRootRaw = decodedText ? extractSoapBodyRoot(decodedText) : undefined
      let soapAction: string | undefined
      if (claimedRaw) {
        const s = scrubText(truncateUtf8HeadTail(claimedRaw, 128), input.vault)
        vaultRedactions += s.vaultRedactions
        if (!isSensitiveValue(s.text)) soapAction = s.text
      }
      const rootIdent = validateStructuralIdent(bodyRootRaw, /^[A-Za-z_][\w.-]{0,47}(?::[A-Za-z_][\w.-]{0,47})?$/, input.vault)
      vaultRedactions += rootIdent.vaultRedactions
      const bodyRoot = rootIdent.value
      const rootLocal = bodyRoot?.includes(':') ? bodyRoot.split(':')[1] : bodyRoot
      const actionMismatch = Boolean(soapAction && rootLocal && !soapAction.toLowerCase().includes(rootLocal.toLowerCase()))
      actions.push({
        family: 'soap',
        op: `soap:${bodyRoot || soapAction || 'unknown'}`,
        resource: input.sanitizedPath,
        details: {
          ...(soapAction && { soapAction }),
          ...(bodyRoot && { bodyRootQName: bodyRoot }),
          ...(actionMismatch && { actionMismatch: true }),
        },
        coverage: defaultCov,
      })
      extractStatus = bodyRoot || soapAction ? (fullyIntact ? 'complete' : 'partial') : 'opaque'
    }

    // 5. Generic REST fallback (for writes)
    else if (input.isWrite) {
      actions.push({
        family: 'rest',
        op: `rest:${input.effectiveMethod}`,
        resource: input.sanitizedPath,
        coverage: isBinary || structuredJsonParseFailed ? 'partial' : defaultCov,
      })
      extractStatus = isBinary || structuredJsonParseFailed ? 'opaque' : fullyIntact ? 'complete' : 'partial'
    }

    // Compute reqBody / reqOmitted / reqTrunc
    let reqBody: string | undefined
    let reqTrunc: true | undefined
    let reqOmitted: BodyOmittedReason | undefined

    if (input.isWrite && (hasBody || input.isLive)) {
      if (input.isLive) {
        reqOmitted = 'live'
      } else if (input.isAuth) {
        reqOmitted = 'auth-url'
      } else if (isBinary) {
        reqOmitted = 'binary'
      } else if (input.projection === 'semantic') {
        reqOmitted = 'policy-profile'
      } else if (structuredJsonParseFailed) {
        // Never fall back to plaintext on truncated/malformed JSON where sensitive-key inheritance would be lost!
        reqOmitted = 'policy-profile'
        reqTrunc = true
      } else if (input.sampleBudgetOk === false) {
        reqOmitted = 'budget'
      } else if (decodedText !== undefined) {
        let redactedText: string
        if (isJson) {
          const rj = redactJsonValue(parsedJson, input.vault, false)
          vaultRedactions += rj.vaultRedactions
          redactedText = JSON.stringify(rj.value)
        } else if (input.reqType === 'application/x-www-form-urlencoded') {
          const rf = redactFormBody(decodedText, input.vault)
          vaultRedactions += rf.vaultRedactions
          redactedText = rf.text
        } else {
          const rp = redactPlainText(decodedText, input.vault)
          vaultRedactions += rp.vaultRedactions
          redactedText = rp.text
        }
        if (Buffer.byteLength(redactedText, 'utf8') > MAX_SAMPLE_BODY_BYTES) {
          reqBody = truncateUtf8HeadTail(redactedText, MAX_SAMPLE_BODY_BYTES, 3072, 1020)
          reqTrunc = true
        } else {
          reqBody = redactedText
        }
      }
    }

    if ((!input.bodyComplete || !decodeComplete) && (hasBody || input.transport === 'truncated')) {
      reqTrunc = true
    }

    return {
      actions,
      ...(bodyShape && Object.keys(bodyShape).length > 0 && { bodyShape }),
      ...(graphqlOp && { graphqlOp }),
      ...(dupKeys && { dupKeys: true as const }),
      completeness: {
        transport: input.transport,
        decode: decodeStatus,
        extract: extractStatus,
        ...(reasons.length > 0 && { reasons }),
      },
      decodeComplete,
      ...(reqBody !== undefined && { reqBody }),
      ...(reqTrunc && { reqTrunc }),
      ...(reqOmitted && { reqOmitted }),
      vaultRedactions,
      ...(isJson && !input.isLive && { parsedBody: parsedJson }),
      ...(decodedText !== undefined && !input.isLive && { rawBodyText: decodedText }),
    }
  } catch {
    return {
      actions: input.isWrite
        ? [{ family: 'rest', op: `rest:${input.effectiveMethod}`, resource: input.sanitizedPath, coverage: 'unknown' }]
        : [],
      completeness: {
        transport: input.transport,
        decode: input.decodeResult?.decode ?? 'none',
        extract: 'none',
        reasons: [...reasons, 'extractor-error'],
      },
      decodeComplete: false,
      vaultRedactions,
    }
  }
}
