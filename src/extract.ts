import zlib from 'node:zlib'
import {
  buildBodyShape,
  buildFormBodyShape,
  isDataLikeKey,
  isSensitiveValue,
  parseJsonSafe,
  scrubStructuralKey,
  scrubText,
  truncateUtf8HeadTail,
} from './redact.ts'

export const EXTRACTOR_V = 1
export const MAX_PREFIX_BYTES = 65_536

export type BodyOmittedReason =
  | 'live'
  | 'auth-url'
  | 'binary'
  | 'budget'
  | 'encoded'
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
}

const SYNC_CODECS: Record<string, (buf: Buffer, opts: zlib.ZlibOptions | zlib.BrotliOptions) => Buffer> = {
  gzip: zlib.gunzipSync,
  'x-gzip': zlib.gunzipSync,
  deflate: zlib.inflateSync,
  br: zlib.brotliDecompressSync,
}

export function decompressPrefix(
  rawBuf: Buffer,
  contentEncoding: string | undefined,
  bodyComplete: boolean,
  maxBytes = MAX_PREFIX_BYTES,
): DecompressResult {
  if (rawBuf.length === 0) {
    return { ok: true, buf: rawBuf, decodeComplete: bodyComplete, decode: 'none', truncated: !bodyComplete }
  }
  const encodings = (contentEncoding ?? '')
    .split(',')
    .map(s => s.trim().toLowerCase())
    .filter(s => s && s !== 'identity')
  if (encodings.length === 0) {
    const within = rawBuf.length <= maxBytes
    return {
      ok: true,
      buf: rawBuf.subarray(0, maxBytes),
      decodeComplete: bodyComplete && within,
      decode: bodyComplete && within ? 'complete' : 'truncated',
      truncated: !bodyComplete || !within,
    }
  }
  if (encodings.length !== 1 || !(encodings[0] in SYNC_CODECS)) {
    return { ok: false, buf: Buffer.alloc(0), decodeComplete: false, decode: 'error', truncated: false, reason: 'encoded' }
  }
  const enc = encodings[0]
  const fn = SYNC_CODECS[enc]
  const flush = enc === 'br' ? zlib.constants.BROTLI_OPERATION_FLUSH : zlib.constants.Z_SYNC_FLUSH
  try {
    const buf = fn(rawBuf, bodyComplete ? { maxOutputLength: maxBytes } : { maxOutputLength: maxBytes, finishFlush: flush })
    return {
      ok: true,
      buf,
      decodeComplete: bodyComplete,
      decode: bodyComplete ? 'complete' : 'truncated',
      truncated: !bodyComplete,
    }
  } catch {
    return { ok: false, buf: Buffer.alloc(0), decodeComplete: false, decode: 'error', truncated: false, reason: 'encoded' }
  }
}

const SAFE_MIME_RE = /^(?:application|audio|font|image|message|model|multipart|text|video)\/[a-z0-9!#$&^_.+-]{1,64}$/

export function normalizeContentType(header: string | undefined): string | undefined {
  if (!header) return undefined
  const e = header.split(';')[0].trim().toLowerCase()
  return e ? (SAFE_MIME_RE.test(e) ? e : 'other') : undefined
}

export function isBinaryContentType(reqType: string | undefined): boolean {
  if (!reqType) return false
  if (reqType === 'multipart/form-data') return true
  if (reqType.startsWith('image/') || reqType.startsWith('video/') || reqType.startsWith('audio/') || reqType.startsWith('font/')) return true
  return (
    reqType === 'application/octet-stream' ||
    reqType === 'application/pdf' ||
    reqType === 'application/zip' ||
    reqType === 'application/gzip' ||
    reqType === 'application/wasm'
  )
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
  return buf.includes(0x00)
}

export function decodeUtf8Prefix(buf: Buffer, truncated: boolean): string | null {
  if (!buf.length) return ''
  const dec = new TextDecoder('utf-8', { fatal: true })
  const maxTrim = truncated ? Math.min(3, buf.length) : 0
  for (let trim = 0; trim <= maxTrim; trim++) {
    try {
      return dec.decode(trim ? buf.subarray(0, buf.length - trim) : buf)
    } catch {}
  }
  return null
}

const GQL_STRIP_RE = /"""(?:\\"""|[\s\S])*?"""|"(?:\\.|[^"\\])*"|#[^\r\n]*/g
const GQL_TOP_HEADER_RE = /\b(?:(fragment)\b|(query|mutation|subscription)(?:\s+([A-Za-z_]\w*))?)/g

export function classifyGraphqlQuery(
  query: string,
  operationName?: string,
): { op: GraphqlOp; opNames: string[]; opKinds: string[] } {
  const stripped = query.replace(GQL_STRIP_RE, ' ')
  const ops: Array<{ kind: 'query' | 'mutation' | 'subscription'; name?: string }> = []
  let depth = 0
  let pDepth = 0
  let headerStart = 0

  for (let i = 0; i < stripped.length; i++) {
    const ch = stripped[i]
    if (ch === '(') { pDepth++; continue }
    if (ch === ')') { if (pDepth > 0) pDepth--; continue }
    if (pDepth > 0) continue
    if (ch === '{') {
      if (depth === 0) {
        const hdr = stripped.slice(headerStart, i)
        let match: RegExpExecArray | null
        let isFrag = false
        let kind: 'query' | 'mutation' | 'subscription' = 'query'
        let name: string | undefined
        GQL_TOP_HEADER_RE.lastIndex = 0
        while ((match = GQL_TOP_HEADER_RE.exec(hdr))) {
          if (match[1]) { isFrag = true; break }
          if (match[2]) {
            kind = match[2] as 'query' | 'mutation' | 'subscription'
            name = match[3]
            break
          }
        }
        if (!isFrag) ops.push({ kind, name })
      }
      depth++
    } else if (ch === '}') {
      if (depth > 0) depth--
      if (depth === 0) headerStart = i + 1
    }
  }

  const opNames = ops.map(o => o.name ?? '<anonymous>')
  const opKinds = ops.map(o => o.kind)
  if (ops.length === 0) return { op: 'mixed', opNames, opKinds }
  if (operationName) {
    const matches = ops.filter(o => o.name === operationName)
    return { op: matches.length === 1 ? matches[0].kind : 'mixed', opNames, opKinds }
  }
  return { op: ops.length === 1 ? ops[0].kind : 'mixed', opNames, opKinds }
}

const SOAP_BODY_ROOT_RE = /<(?:[\w.-]+:)?Body(?:\s[^<>]*)?>\s*(?:<!--[\s\S]*?-->\s*)*<([\w.:-]+)/i

export function extractSoapBodyRoot(xml: string): string | undefined {
  return SOAP_BODY_ROOT_RE.exec(xml)?.[1]
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
}

export type ExtractOutput = {
  actions: SemanticAction[]
  bodyShape?: Record<string, string>
  graphqlOp?: GraphqlOp
  dupKeys?: true
  completeness: Completeness
  decodeComplete: boolean
  reqTrunc?: true
  reqOmitted?: BodyOmittedReason
}

const E1_ENDPOINTS = new Set(['formservice', 'appstack', 'dataservice', 'orchestrator', 'file', 'tokenrequest', 'discover', 'defaultconfig'])
const STRUCT_IDENT_RE = /^[A-Za-z][A-Za-z0-9_.-]{0,47}$/
const E1_CONTROL_ID_RE = /^[A-Za-z0-9_.-]{1,32}$/
const GQL_IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]{0,47}$/

function validateStructuralIdent(val: unknown, pattern: RegExp, allowNumeric = false): string | undefined {
  if (typeof val !== 'string' || !val) return undefined
  if (!pattern.test(val) || isSensitiveValue(val)) return undefined
  if (!allowNumeric && isDataLikeKey(val)) return undefined
  return val
}

export function extractSemantic(input: ExtractInput): ExtractOutput {
  const reasons: string[] = [...(input.transportReasons ?? [])]

  if (input.kind === 'upgrade') {
    return {
      actions: [{ family: 'upgrade', op: 'upgrade:websocket', resource: input.sanitizedPath, coverage: 'complete' }],
      completeness: { transport: 'not-read', decode: 'none', extract: 'complete', ...(reasons.length && { reasons }) },
      decodeComplete: true,
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
        reqOmitted: input.isLive ? 'live' : input.isAuth ? 'auth-url' : 'encoded',
      }
    }

    const hasBody = rawBuf.length > 0
    let isBinary = false
    let decodedText: string | undefined
    if (hasBody) {
      if (isBinaryContentType(input.reqType) || hasBinaryMagic(rawBuf)) {
        isBinary = true
        reasons.push(input.reqType === 'multipart/form-data' ? 'multipart' : 'binary')
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
        bodyShape = buildBodyShape(parsedJson).shape
      } else if (decodedText !== undefined && input.reqType === 'application/x-www-form-urlencoded') {
        bodyShape = buildFormBodyShape(decodedText).shape
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

      const formIdent = validateStructuralIdent(rawFormName, STRUCT_IDENT_RE)
      if (formIdent) details.formName = formIdent
      const verIdent = validateStructuralIdent(obj?.version, STRUCT_IDENT_RE)
      if (verIdent) details.version = verIdent
      const rawAction = typeof obj?.action === 'string' ? obj.action : typeof obj?.formServiceAction === 'string' ? obj.formServiceAction : undefined
      const actIdent = validateStructuralIdent(rawAction, /^[A-Za-z][A-Za-z0-9_-]{0,23}$/)
      if (actIdent) details.action = actIdent
      const targetTypeIdent = validateStructuralIdent(obj?.targetType, STRUCT_IDENT_RE)
      if (targetTypeIdent) details.targetType = targetTypeIdent
      const dsTypeIdent = validateStructuralIdent(obj?.dataServiceType, STRUCT_IDENT_RE)
      if (dsTypeIdent) details.dataServiceType = dsTypeIdent

      const rawActions = Array.isArray(obj?.formActions)
        ? obj.formActions
        : Array.isArray((obj?.actionRequest as any)?.formActions)
          ? (obj!.actionRequest as any).formActions
          : Array.isArray((obj?.formRequest as any)?.formActions)
            ? (obj!.formRequest as any).formActions
            : undefined
      if (rawActions) {
        details.formActions = rawActions.slice(0, 32).map(a => {
          if (!a || typeof a !== 'object') return { command: 'unknown' }
          const rec = a as Record<string, unknown>
          const item: Record<string, string> = {}
          const cmd = validateStructuralIdent(rec.command, STRUCT_IDENT_RE)
          if (cmd) item.command = cmd
          const cid = validateStructuralIdent(rec.controlID, E1_CONTROL_ID_RE, true)
          if (cid) item.controlID = cid
          return item
        })
        if (rawActions.length > 32) details.formActionsTruncated = true
      }

      actions.push({
        family: 'e1-ais',
        op: actIdent ? `${endpoint}:${actIdent}` : `${endpoint}:${input.effectiveMethod}`,
        resource: formIdent ?? input.sanitizedPath,
        ...(Object.keys(details).length && { details }),
        coverage: defaultCov,
      })
      extractStatus = fullyIntact ? 'complete' : 'partial'
    }

    // 2. SharePoint REST API
    else if (lowerPath.includes('/_api/') || lowerPath.includes('/_vti_bin/')) {
      const sanLower = input.sanitizedPath.toLowerCase()
      const apiIdx = sanLower.indexOf('/_api/') >= 0 ? sanLower.indexOf('/_api/') : sanLower.indexOf('/_vti_bin/')
      const spResource = apiIdx >= 0 ? input.sanitizedPath.slice(apiIdx) : input.sanitizedPath
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
        const metaIdent = validateStructuralIdent(rawMetaType, /^[#A-Za-z][A-Za-z0-9_.-]{0,63}$/)
        if (metaIdent) details.metadataType = metaIdent

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

    // 3. GraphQL
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
        const safeOpName = validateStructuralIdent(opNameRaw, GQL_IDENT_RE)

        let varKeys: string[] | undefined
        if (idx < 16 && rec.variables && typeof rec.variables === 'object' && !Array.isArray(rec.variables)) {
          varKeys = Object.keys(rec.variables as Record<string, unknown>).slice(0, 32).map(k => scrubStructuralKey(k).key)
        }

        if (!qStr && hasPersisted) {
          opsSeen.push('persisted')
          if (idx < 16) {
            actions.push({
              family: 'graphql',
              op: 'graphql:persisted',
              resource: safeOpName ?? input.sanitizedPath,
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
            const safeNames = res.opNames.slice(0, 16).map(n => n === '<anonymous>' ? n : (validateStructuralIdent(n, GQL_IDENT_RE) ?? '<redacted>'))
            const resource = safeOpName ?? (safeNames.length === 1 && safeNames[0] !== '<anonymous>' && safeNames[0] !== '<redacted>' ? safeNames[0] : input.sanitizedPath)
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
            actions.push({ family: 'graphql', op: 'graphql:mixed', resource: input.sanitizedPath, coverage: 'unknown' })
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
        const s = scrubText(truncateUtf8HeadTail(claimedRaw, 128)).text
        if (!isSensitiveValue(s)) soapAction = s
      }
      const bodyRoot = validateStructuralIdent(bodyRootRaw, /^[A-Za-z_][\w.-]{0,47}(?::[A-Za-z_][\w.-]{0,47})?$/)
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

    let reqTrunc: true | undefined
    let reqOmitted: BodyOmittedReason | undefined
    if (input.isWrite && (hasBody || input.isLive)) {
      if (input.isLive) reqOmitted = 'live'
      else if (input.isAuth) reqOmitted = 'auth-url'
      else if (isBinary) reqOmitted = 'binary'
      else reqOmitted = 'policy-profile'
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
      ...(reqTrunc && { reqTrunc }),
      ...(reqOmitted && { reqOmitted }),
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
    }
  }
}
