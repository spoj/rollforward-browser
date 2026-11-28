import zlib from 'node:zlib'
import {
  isDataLikeKey,
  isSensitiveValue,
  parseJsonSafe,
  scrubStructuralKey,
  scrubText,
  truncateUtf8HeadTail,
} from './shared/redact.ts'
import {
  E1_MUTATING_FORM_COMMANDS,
  MAX_PREFIX_BYTES,
  computeTargetDigest,
  decodeUtf8Prefix,
  extractSemantic as sharedExtractSemantic,
  type Completeness,
  type SemanticAction,
} from './shared/classify.ts'

export {
  DESC_V,
  E1_MUTATING_FORM_COMMANDS,
  EXTRACTOR_V,
  MAX_PREFIX_BYTES,
  SAFE_METHODS,
  canonicalSqlPayload,
  canonicalTargetPayload,
  classifySqlStatement,
  computeSqlContextDigest,
  computeTargetDigest,
  decodePathSegmentsStrict,
  decodeUtf8Prefix,
  extractSharePointRestSubpath,
  hasBinaryMagic,
  hasIfNoneMatchStar,
  hasStrongIfMatch,
  isBinaryContentType,
  parseSemanticMethods,
  validateSharePointDeleteIds,
  type Completeness,
  type SafeRequestProjection as SharedSafeRequestProjection,
  type SemanticAction,
  type SemanticMethodInfo,
  type SqlClassification,
} from './shared/classify.ts'

export type BodyOmittedReason =
  | 'live'
  | 'auth-url'
  | 'binary'
  | 'budget'
  | 'encoded'
  | 'timeout'
  | 'policy-profile'

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

const STRUCT_IDENT_RE = /^[A-Za-z][A-Za-z0-9_.-]{0,47}$/
const E1_CONTROL_ID_RE = /^[A-Za-z0-9_.-]{1,32}$/
const GQL_IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]{0,47}$/

function validateStructuralIdent(val: unknown, pattern: RegExp, allowNumeric = false): string | undefined {
  if (typeof val !== 'string' || !val) return undefined
  if (!pattern.test(val) || isSensitiveValue(val)) return undefined
  if (!allowNumeric && isDataLikeKey(val)) return undefined
  return val
}

function classifyBrowserE1BodyShape(
  obj: Record<string, unknown>,
  input: ExtractInput,
  defaultCov: SemanticAction['coverage'],
): SemanticAction {
  const details: Record<string, unknown> = {}
  const rawFormName = typeof obj.formName === 'string'
    ? obj.formName
    : typeof (obj.formRequest as any)?.formName === 'string'
      ? (obj.formRequest as any).formName
      : typeof obj.targetName === 'string'
        ? obj.targetName
        : undefined
  const formIdent = validateStructuralIdent(rawFormName, STRUCT_IDENT_RE)
  if (formIdent) details.formName = formIdent
  const verIdent = validateStructuralIdent(obj.version, STRUCT_IDENT_RE)
  if (verIdent) details.version = verIdent
  const rawAction = typeof obj.action === 'string' ? obj.action : typeof obj.formServiceAction === 'string' ? obj.formServiceAction : undefined
  const actIdent = validateStructuralIdent(rawAction, /^[A-Za-z][A-Za-z0-9_-]{0,23}$/)
  if (actIdent) details.action = actIdent
  const targetTypeIdent = validateStructuralIdent(obj.targetType, STRUCT_IDENT_RE)
  if (targetTypeIdent) details.targetType = targetTypeIdent
  const dsTypeIdent = validateStructuralIdent(obj.dataServiceType, STRUCT_IDENT_RE)
  if (dsTypeIdent) details.dataServiceType = dsTypeIdent

  const rawActions = Array.isArray(obj.formActions)
    ? obj.formActions
    : Array.isArray((obj.actionRequest as any)?.formActions)
      ? (obj.actionRequest as any).formActions
      : Array.isArray((obj.formRequest as any)?.formActions)
        ? (obj.formRequest as any).formActions
        : undefined
  let hasMutatingFormAction = false
  if (rawActions) {
    details.formActions = rawActions.slice(0, 32).map(a => {
      if (!a || typeof a !== 'object') return { command: 'unknown' }
      const rec = a as Record<string, unknown>
      const item: Record<string, string> = {}
      const cmd = validateStructuralIdent(rec.command, STRUCT_IDENT_RE)
      if (cmd) {
        item.command = cmd
        if (E1_MUTATING_FORM_COMMANDS.has(cmd.toLowerCase())) hasMutatingFormAction = true
      }
      const cid = validateStructuralIdent(rec.controlID, E1_CONTROL_ID_RE, true)
      if (cid) item.controlID = cid
      return item
    })
    if (hasMutatingFormAction) details.hasMutatingFormAction = true
    if (rawActions.length > 32) details.formActionsTruncated = true
  }
  const mutates = hasMutatingFormAction || Boolean(actIdent && ['W', 'C', 'U', 'D'].includes(actIdent.toUpperCase()))
  if (mutates && formIdent) details.mutatingForms = [formIdent]
  if (input.isWrite) {
    details.targetDigest = computeTargetDigest({
      surface: 'browser',
      host: input.url.hostname,
      port: input.url.port,
      scheme: input.url.protocol.replace(/:$/, ''),
      rawPathname: input.url.pathname,
      rawSearch: input.url.search,
      resourceId: formIdent,
    })
  }

  return {
    family: 'e1-ais',
    op: actIdent ? `ais:${actIdent}` : `ais:${input.effectiveMethod}`,
    resource: formIdent ?? input.sanitizedPath,
    ...(Object.keys(details).length && { details }),
    coverage: defaultCov,
  }
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
    const effectiveBodyComplete = input.bodyComplete && decodeComplete

    // Delegate shared core classification (ambiguous path encoding, SharePoint, /jderest/ E1 AIS,
    // binary/UTF-8/JSON parsing, bodyShape, dupKeys, REST fallback).
    const shared = sharedExtractSemantic({
      url: input.url,
      sanitizedPath: input.sanitizedPath,
      method: input.method,
      effectiveMethod: input.effectiveMethod,
      kind: input.kind,
      surface: 'browser',
      hdr: input.hdr,
      rawHeaders: input.rawHeaders,
      reqType: input.reqType,
      decodedBuf: rawBuf,
      bodyComplete: effectiveBodyComplete,
      transport: input.transport,
      transportReasons: reasons,
      isWrite: input.isWrite,
      isLive: input.isLive,
    })

    const sharedReasons = shared.completeness.reasons ?? []
    const isBinary = sharedReasons.includes('binary') || sharedReasons.includes('multipart') || sharedReasons.includes('invalid-utf8')
    const dupKeys = shared.dupKeys === true
    const fullyIntact = effectiveBodyComplete && !dupKeys
    const defaultCov: SemanticAction['coverage'] = fullyIntact ? 'complete' : 'partial'

    let actions = shared.actions
    let extractStatus = shared.completeness.extract
    let graphqlOp: GraphqlOp | undefined
    const outReasons = [...sharedReasons]

    // Browser-only classifiers run only when shared fell through to generic REST or empty actions.
    const isGenericFallback =
      actions.length === 0 ||
      (actions.length === 1 && actions[0].family === 'rest' && actions[0].op !== 'ambiguous_path_encoding')

    if (isGenericFallback) {
      const decodedText = hasBody && !isBinary ? decodeUtf8Prefix(rawBuf, !effectiveBodyComplete) ?? undefined : undefined
      const parsed = decodedText !== undefined ? parseJsonSafe(decodedText) : undefined
      const parsedJson = parsed?.ok ? parsed.value : undefined
      const obj = parsed?.ok && parsedJson && typeof parsedJson === 'object' && !Array.isArray(parsedJson)
        ? (parsedJson as Record<string, unknown>)
        : undefined
      const lowerPath = input.url.pathname.toLowerCase()

      // 1. Body-shape E1 AIS detection (non-/jderest/ paths)
      const isE1Shape = Boolean(
        obj &&
        typeof obj.formName === 'string' &&
        (Array.isArray(obj.formActions) || typeof obj.formServiceAction === 'string' || 'actionRequest' in obj || 'formRequest' in obj),
      )

      if (isE1Shape && obj) {
        actions = [classifyBrowserE1BodyShape(obj, input, defaultCov)]
        extractStatus = fullyIntact ? 'complete' : 'partial'
      }

      // 2. GraphQL
      else if (
        lowerPath.includes('/graphql') ||
        (obj && (typeof obj.query === 'string' || (obj.extensions && typeof obj.extensions === 'object' && 'persistedQuery' in (obj.extensions as Record<string, unknown>)))) ||
        (Array.isArray(parsedJson) && parsedJson.length > 0 && parsedJson.every(item => item && typeof item === 'object' && ('query' in (item as any) || 'extensions' in (item as any))))
      ) {
        const allItems = Array.isArray(parsedJson) ? parsedJson : obj ? [obj] : []
        const batchTruncated = allItems.length > 16
        if (batchTruncated) outReasons.push('batch-truncated')
        const gqlActions: SemanticAction[] = []
        const opsSeen: GraphqlOp[] = []

        for (let idx = 0; idx < allItems.length; idx++) {
          const rec = allItems[idx] as Record<string, unknown>
          const qStr = typeof rec.query === 'string' ? rec.query : undefined
          const opNameRaw = typeof rec.operationName === 'string' ? rec.operationName : undefined
          const hasPersisted = Boolean(rec.extensions && typeof rec.extensions === 'object' && 'persistedQuery' in (rec.extensions as Record<string, unknown>))
          const safeOpName = validateStructuralIdent(opNameRaw, GQL_IDENT_RE)

          let varKeys: string[] | undefined
          if (idx < 16 && rec.variables && typeof rec.variables === 'object' && !Array.isArray(rec.variables)) {
            varKeys = Object.keys(rec.variables as Record<string, unknown>).slice(0, 32).map(k => scrubStructuralKey(k))
          }

          if (!qStr && hasPersisted) {
            opsSeen.push('persisted')
            if (idx < 16) {
              gqlActions.push({
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
              gqlActions.push({
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
              gqlActions.push({ family: 'graphql', op: 'graphql:mixed', resource: input.sanitizedPath, coverage: 'unknown' })
            }
          }
        }

        actions = gqlActions
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

      // 3. SOAP
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
        actions = [{
          family: 'soap',
          op: `soap:${bodyRoot || soapAction || 'unknown'}`,
          resource: input.sanitizedPath,
          details: {
            ...(soapAction && { soapAction }),
            ...(bodyRoot && { bodyRootQName: bodyRoot }),
            ...(actionMismatch && { actionMismatch: true }),
          },
          coverage: defaultCov,
        }]
        extractStatus = bodyRoot || soapAction ? (fullyIntact ? 'complete' : 'partial') : 'opaque'
      }
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
      ...(shared.bodyShape && Object.keys(shared.bodyShape).length > 0 && { bodyShape: shared.bodyShape }),
      ...(graphqlOp && { graphqlOp }),
      ...(dupKeys && { dupKeys: true as const }),
      completeness: {
        transport: input.transport,
        decode: decodeStatus,
        extract: extractStatus,
        ...(outReasons.length > 0 && { reasons: outReasons }),
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
