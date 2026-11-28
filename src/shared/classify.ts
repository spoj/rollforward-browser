import crypto from 'node:crypto'
import {
  buildBodyShape,
  buildFormBodyShape,
  isDataLikeKey,
  isSensitiveValue,
  parseJsonSafe,
  sanitizeUrl,
  scrubStructuralKey,
  scrubText,
  truncateUtf8HeadTail,
  REDACT_V,
} from './redact.ts'

export { sanitizeUrl, REDACT_V }

export const DESC_V = 1
export const EXTRACTOR_V = 1
export const MAX_PREFIX_BYTES = 65_536

export const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const OVERRIDE_HEADERS = ['x-http-method', 'x-http-method-override', 'x-method-override'] as const
const VALID_VERB_RE = /^[A-Z]{3,16}$/

export type SemanticAction = {
  family: 'e1-ais' | 'sharepoint' | 'graphql' | 'soap' | 'rest' | 'api' | 'upgrade' | 'graph' | 'databricks' | 'service'
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
  overrideInvalid?: true
  overrideDowngrade?: true
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
  graphqlOp?: 'query' | 'mutation' | 'subscription' | 'mixed' | 'persisted'
  dupKeys?: true
  live?: true
}

export type RequestDescriptor = {
  safe: SafeRequestProjection
}

export type SemanticMethodInfo = {
  wireMethod: string
  effectiveMethod: string
  methodSource: SafeRequestProjection['methodSource']
  hdr?: Record<string, string>
  hdrConflict: boolean
  invalidOrConflictingOverride: boolean
  attemptedDowngrade: boolean
  overrideEscalated: boolean
}

export function parseSemanticMethods(
  method: string | undefined,
  headers: Record<string, string | string[] | undefined>,
): SemanticMethodInfo {
  const wireMethod = (method ?? 'GET').toUpperCase()
  const hdr: Record<string, string> = {}
  let invalid = false
  const validTokens: Array<{ header: typeof OVERRIDE_HEADERS[number]; verb: string }> = []

  for (const name of OVERRIDE_HEADERS) {
    const rawVal = headers[name]
    if (rawVal === undefined) continue
    const joined = Array.isArray(rawVal) ? rawVal.join(',') : rawVal
    hdr[name] = scrubText(truncateUtf8HeadTail(joined, 256)).text

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

  const distinctVerbs = [...new Set(validTokens.map(v => v.verb))]
  const hdrConflict = distinctVerbs.length > 1
  const invalidOrConflictingOverride = invalid || hdrConflict

  let effectiveMethod = wireMethod
  let methodSource: SafeRequestProjection['methodSource'] = 'wire'
  let attemptedDowngrade = false
  let overrideEscalated = false

  if (validTokens.length > 0) {
    const unsafe = validTokens.find(v => !SAFE_METHODS.has(v.verb))
    if (unsafe) {
      effectiveMethod = unsafe.verb
      methodSource = unsafe.header
      if (SAFE_METHODS.has(wireMethod)) overrideEscalated = true
    } else if (SAFE_METHODS.has(wireMethod)) {
      effectiveMethod = validTokens[0].verb
      methodSource = validTokens[0].header
    } else {
      effectiveMethod = wireMethod
      methodSource = 'wire'
      attemptedDowngrade = true
    }
  }

  return {
    wireMethod,
    effectiveMethod,
    methodSource,
    hdr: Object.keys(hdr).length ? hdr : undefined,
    hdrConflict,
    invalidOrConflictingOverride,
    attemptedDowngrade,
    overrideEscalated,
  }
}

const SAFE_MIME_RE = /^[a-z0-9!#$&^_.+-]{1,40}\/[a-z0-9!#$&^_.+-]{1,64}$/
const STANDARD_MIME_TYPES = new Set(['application', 'audio', 'font', 'image', 'message', 'model', 'multipart', 'text', 'video'])

export function normalizeContentType(header: string | undefined): string | undefined {
  if (!header) return undefined
  const rawEssence = header.split(';')[0].trim()
  if (!rawEssence) return undefined
  const essence = rawEssence.toLowerCase()
  if (!SAFE_MIME_RE.test(essence)) return 'application/octet-stream'
  const slashIdx = rawEssence.indexOf('/')
  const rawSub = slashIdx >= 0 ? rawEssence.slice(slashIdx + 1) : ''
  const [type, subtype] = essence.split('/')
  if (!STANDARD_MIME_TYPES.has(type)) return 'application/octet-stream'
  if (isSensitiveValue(rawSub) || isSensitiveValue(subtype) || isDataLikeKey(rawSub) || isDataLikeKey(subtype)) {
    return `${type}/<redacted>`
  }
  return essence
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
    } catch {
      // retry with one fewer trailing byte if truncated mid-codepoint
    }
  }
  return null
}

export function canonicalizeTargetPath(rawPathname: string, foldGraphVersion = false): string {
  let p = rawPathname.trim()
  if (!p.startsWith('/')) p = '/' + p
  if (foldGraphVersion) {
    p = p.replace(/^\/(v1\.0|beta)(?=\/|$)/i, (_, v: string) => `/${v.toLowerCase()}`)
  }
  return p
}

export function effectiveAuthority(host: string, port?: string | number, scheme = 'https'): string {
  const h = host.trim().toLowerCase()
  if (!h) return ''
  const rawPort = port !== undefined && port !== null ? String(port).trim() : ''
  const effPort = rawPort || (scheme === 'http' ? '80' : scheme === 'https' ? '443' : '')
  return effPort ? `${h}:${effPort}` : h
}

export function decodePathSegmentsStrict(rawPathname: string): { segments: string[]; decodedPath: string; invalidEncoding: boolean } {
  const parts = rawPathname.split('/')
  const segments: string[] = []
  let invalidEncoding = false
  for (const seg of parts) {
    if (!seg) continue
    try {
      const dec = decodeURIComponent(seg)
      if (/[/\\\x00-\x1f\x7f]/.test(dec) || /%[0-9a-fA-F]{2}/.test(dec) || dec === '.' || dec === '..') {
        invalidEncoding = true
      }
      segments.push(dec)
    } catch {
      invalidEncoding = true
      segments.push(seg)
    }
  }
  return { segments, decodedPath: '/' + segments.join('/'), invalidEncoding }
}

function isPlainRecord(v: unknown): v is Record<string, unknown> {
  return Boolean(v && typeof v === 'object' && !Array.isArray(v))
}

export function validateSharePointDeleteIds(
  rawIds: unknown,
  rejectValue?: (id: string) => boolean,
): { ok: true; ids: string[]; bodySelector: string } | { ok: false; reason: string } {
  if (!Array.isArray(rawIds) || rawIds.length === 0 || rawIds.length > 64) {
    return { ok: false, reason: 'SharePoint DeleteByIds scope requires 1..64 explicit concrete ids' }
  }
  const idSet = new Set<string>()
  for (const item of rawIds) {
    let sId: string
    if (typeof item === 'string' && item.trim() && item.trim().length <= 128 && !item.includes('*') && !/[\r\n\0]/.test(item)) {
      sId = item.trim()
    } else if (typeof item === 'number' && Number.isSafeInteger(item)) {
      sId = String(item)
    } else {
      return { ok: false, reason: 'SharePoint DeleteByIds ids must be concrete non-empty strings or integers (no wildcards)' }
    }
    if (rejectValue?.(sId)) {
      return { ok: false, reason: 'execpolicy ids must not contain raw secrets or credentials' }
    }
    idSet.add(sId)
  }
  if (idSet.size === 0) {
    return { ok: false, reason: 'SharePoint DeleteByIds scope requires 1..64 explicit concrete ids' }
  }
  const ids = [...idSet].sort()
  return { ok: true, ids, bodySelector: JSON.stringify({ op: 'deletebyids', ids }) }
}

export function extractSharePointRestSubpath(decodedPath: string): string {
  const lower = decodedPath.toLowerCase()
  const apiIdx = lower.indexOf('/_api/')
  const vtiIdx = lower.indexOf('/_vti_bin/')
  const idx = apiIdx >= 0 && vtiIdx >= 0 ? Math.min(apiIdx, vtiIdx) : apiIdx >= 0 ? apiIdx : vtiIdx
  return idx >= 0 ? decodedPath.slice(idx) : ''
}

export const MAX_CANONICAL_DEPTH = 16
const MAX_CANONICAL_NODES = 512

export function canonicalizeJsonValue(val: unknown, depth = 0, state = { nodes: 0 }): unknown {
  if (depth > MAX_CANONICAL_DEPTH) throw new RangeError(`JSON nesting depth exceeds ${MAX_CANONICAL_DEPTH}`)
  if (++state.nodes > MAX_CANONICAL_NODES) throw new RangeError(`JSON structure exceeds ${MAX_CANONICAL_NODES} nodes`)
  if (val === null || val === undefined || typeof val !== 'object') return val
  if (Array.isArray(val)) return val.map(v => canonicalizeJsonValue(v, depth + 1, state))
  const out = Object.create(null) as Record<string, unknown>
  for (const k of Object.keys(val as Record<string, unknown>).sort()) {
    Object.defineProperty(out, k, {
      value: canonicalizeJsonValue((val as Record<string, unknown>)[k], depth + 1, state),
      enumerable: true,
      configurable: true,
      writable: true,
    })
  }
  return out
}

export function canonicalTargetPayload(input: {
  surface: 'browser' | 'api'
  connectionType?: string
  host: string
  port?: string | number
  scheme?: string
  rawPathname: string
  rawSearch?: string
  resourceId?: string
  bodySelector?: string
}): string {
  const connType = (input.connectionType ?? '').toLowerCase()
  const foldGraph = connType === 'graph' || input.host.trim().toLowerCase() === 'graph.microsoft.com'
  const auth = effectiveAuthority(input.host, input.port, input.scheme ?? 'https')
  const tuple: string[] = [
    input.surface,
    connType,
    auth,
    canonicalizeTargetPath(input.rawPathname, foldGraph),
    input.rawSearch ?? '',
    input.resourceId ?? '',
  ]
  if (input.bodySelector) tuple.push(input.bodySelector)
  return `target:${JSON.stringify(tuple)}`
}

export function canonicalSqlPayload(input: {
  sql: string
  parameters?: unknown
  warehouseId?: string
  catalog?: string
  schema?: string
}): string {
  const hasParameters = input.parameters !== undefined
  const payload = JSON.stringify({
    sql: input.sql.trim(),
    hasParameters,
    parameters: hasParameters ? canonicalizeJsonValue(input.parameters) : undefined,
    warehouseId: input.warehouseId ?? '',
    catalog: input.catalog ?? '',
    schema: input.schema ?? '',
  })
  return `sql:${payload}`
}

const sha256Hex = (payload: string) => crypto.createHash('sha256').update(payload).digest('hex')

export function computeTargetDigest(input: Parameters<typeof canonicalTargetPayload>[0]): string {
  return sha256Hex(canonicalTargetPayload(input))
}

export function computeSqlContextDigest(input: Parameters<typeof canonicalSqlPayload>[0]): string {
  return sha256Hex(canonicalSqlPayload(input))
}

// Strict RFC 9110 §8.8.3.2 / §13.1.1 linear strong entity-tag list scanner.
function isRfc9110Etagc(c: number): boolean {
  return c === 0x21 || (c >= 0x23 && c <= 0x7e) || (c >= 0x80 && c <= 0xff)
}

export function hasStrongIfMatch(rawHeaders: Record<string, string | string[] | undefined>): boolean {
  const raw = rawHeaders['if-match']
  const val = Array.isArray(raw) ? raw.join(',') : typeof raw === 'string' ? raw : ''
  const len = val.length
  let i = 0
  const skipOws = () => { while (i < len && (val.charCodeAt(i) === 0x20 || val.charCodeAt(i) === 0x09)) i++ }

  skipOws()
  if (i >= len) return false
  let count = 0
  for (;;) {
    skipOws()
    if (i >= len || val.charCodeAt(i) !== 0x22) return false
    i++
    const tagStart = i
    while (i < len && val.charCodeAt(i) !== 0x22) {
      if (!isRfc9110Etagc(val.charCodeAt(i))) return false
      i++
    }
    if (i >= len || i === tagStart) return false
    i++
    count++
    skipOws()
    if (i >= len) break
    if (val.charCodeAt(i) !== 0x2c) return false
    i++
    skipOws()
    if (i >= len) return false
  }
  return count > 0
}

export function hasIfNoneMatchStar(rawHeaders: Record<string, string | string[] | undefined>): boolean {
  const raw = rawHeaders['if-none-match']
  const val = Array.isArray(raw) ? raw.join(',') : typeof raw === 'string' ? raw : ''
  return val.trim() === '*'
}

export const E1_MUTATING_FORM_COMMANDS = new Set([
  'doaction',
  'setcontrolvalue',
  'setcheckboxvalue',
  'setradiobutton',
  'setcombovalue',
  'setgridcellvalue',
  'insertgridrow',
  'deletegridrow',
  'updategridrow',
  'clickgridcell',
])

// ---- Spark SQL lexer & classifier (zero PII emitted) ----

export type SqlClassification = {
  sqlClass: 'read' | 'write' | 'ddl' | 'unknown'
  statements: string[]
  hasDropOrTruncate: boolean
  hasDelete: boolean
  hasMergeDelete?: boolean
  hasUnknownStatement?: boolean
  ambiguous?: boolean
}

const SQL_READ_VERBS = new Set(['SELECT', 'SHOW', 'DESCRIBE', 'DESC', 'EXPLAIN', 'VALUES', 'LIST'])
const SQL_WRITE_VERBS = new Set(['INSERT', 'UPDATE', 'DELETE', 'MERGE', 'COPY', 'CALL', 'PUT'])
const SQL_DDL_VERBS = new Set(['DROP', 'CREATE', 'ALTER', 'TRUNCATE', 'REPLACE', 'GRANT', 'REVOKE', 'OPTIMIZE', 'VACUUM', 'RESTORE'])

export function classifySqlStatement(sql: string): SqlClassification {
  type Tok = { kind: 'word' | 'lparen' | 'rparen' | 'comma' | 'semi' | 'other'; text: string }
  const tokens: Tok[] = []
  let i = 0
  const len = sql.length
  let ambiguous = false

  while (i < len) {
    const ch = sql[i]
    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') { i++; continue }
    if (ch === '-' && sql[i + 1] === '-') {
      i += 2
      while (i < len) {
        const c0 = sql[i]
        if (c0 === '\\' && (sql[i + 1] === '\n' || sql[i + 1] === '\r')) {
          ambiguous = true
          i++
          i += sql[i] === '\r' && sql[i + 1] === '\n' ? 2 : 1
          continue
        }
        if (c0 === '\r') {
          ambiguous = true
          i += sql[i + 1] === '\n' ? 2 : 1
          break
        }
        if (c0 === '\n') { i++; break }
        i++
      }
      continue
    }
    if (ch === '/' && sql[i + 1] === '*') {
      i += 2
      let commentDepth = 1
      while (i < len && commentDepth > 0) {
        if (sql[i] === '/' && sql[i + 1] === '*') {
          ambiguous = true
          commentDepth++
          i += 2
        } else if (sql[i] === '*' && sql[i + 1] === '/') {
          commentDepth--
          i += 2
        } else {
          i++
        }
      }
      if (commentDepth > 0) ambiguous = true
      continue
    }
    if ((ch === 'r' || ch === 'R') && (sql[i + 1] === "'" || sql[i + 1] === '"')) {
      const q = sql[i + 1]
      i += 2
      let closed = false
      while (i < len) {
        if (sql[i] === q) { i++; closed = true; break }
        i++
      }
      if (!closed) ambiguous = true
      tokens.push({ kind: 'other', text: '' })
      continue
    }
    if (ch === "'") {
      i++
      let closed = false
      while (i < len) {
        if (sql[i] === '\\' || (sql[i] === "'" && sql[i + 1] === "'")) { i += 2; continue }
        if (sql[i] === "'") { i++; closed = true; break }
        i++
      }
      if (!closed) ambiguous = true
      tokens.push({ kind: 'other', text: '' })
      continue
    }
    if (ch === '`') {
      const start = i
      i++
      let closed = false
      while (i < len) {
        if (sql[i] === '`' && sql[i + 1] === '`') { i += 2; continue }
        if (sql[i] === '`') { i++; closed = true; break }
        i++
      }
      if (!closed) ambiguous = true
      tokens.push({ kind: 'word', text: sql.slice(start, i) })
      continue
    }
    if (ch === '"') {
      const start = i
      i++
      let closed = false
      while (i < len) {
        if (sql[i] === '\\' || (sql[i] === '"' && sql[i + 1] === '"')) { i += 2; continue }
        if (sql[i] === '"') { i++; closed = true; break }
        i++
      }
      if (!closed) ambiguous = true
      tokens.push({ kind: 'word', text: sql.slice(start, i) })
      continue
    }
    if (ch === '(') { tokens.push({ kind: 'lparen', text: '(' }); i++; continue }
    if (ch === ')') { tokens.push({ kind: 'rparen', text: ')' }); i++; continue }
    if (ch === ',') { tokens.push({ kind: 'comma', text: ',' }); i++; continue }
    if (ch === ';') { tokens.push({ kind: 'semi', text: ';' }); i++; continue }
    const c = sql.charCodeAt(i)
    if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95) {
      const start = i
      i++
      while (i < len) {
        const cc = sql.charCodeAt(i)
        if ((cc >= 65 && cc <= 90) || (cc >= 97 && cc <= 122) || (cc >= 48 && cc <= 57) || cc === 95) i++
        else break
      }
      tokens.push({ kind: 'word', text: sql.slice(start, i).toUpperCase() })
      continue
    }
    if (!/\s/.test(ch)) tokens.push({ kind: 'other', text: '' })
    i++
  }

  const rawStmts: Tok[][] = []
  let cur: Tok[] = []
  let depth = 0
  for (const t of tokens) {
    if (t.kind === 'lparen') depth++
    else if (t.kind === 'rparen' && depth > 0) depth--
    if (t.kind === 'semi' && depth === 0) {
      if (cur.length) rawStmts.push(cur)
      cur = []
    } else {
      cur.push(t)
    }
  }
  if (cur.length) rawStmts.push(cur)

  const skipParenGroup = (arr: Tok[], idx: number): number => {
    if (arr[idx]?.kind !== 'lparen') return -1
    let d = 1
    let p = idx + 1
    while (p < arr.length && d > 0) {
      if (arr[p].kind === 'lparen') d++
      else if (arr[p].kind === 'rparen') d--
      p++
    }
    return d === 0 ? p : -1
  }

  const statements: string[] = []
  let hasMergeDelete = false
  let hasOverwriteOrReplaceWhere = false

  for (const stmt of rawStmts) {
    const first = stmt[0]
    if (!first || first.kind !== 'word') {
      statements.push('UNKNOWN')
      continue
    }
    let verb = first.text
    let mainIdx = 0
    if (verb === 'WITH') {
      let p = 1
      if (stmt[p]?.kind === 'word' && stmt[p].text === 'RECURSIVE') p++
      let ok = false
      for (;;) {
        if (stmt[p]?.kind !== 'word') { ok = false; break }
        p++
        if (stmt[p]?.kind === 'lparen') {
          p = skipParenGroup(stmt, p)
          if (p < 0) { ok = false; break }
        }
        if (stmt[p]?.kind !== 'word' || stmt[p].text !== 'AS') { ok = false; break }
        p++
        if (stmt[p]?.kind === 'word' && stmt[p].text === 'NOT') p++
        if (stmt[p]?.kind === 'word' && stmt[p].text === 'MATERIALIZED') p++
        if (stmt[p]?.kind !== 'lparen') { ok = false; break }
        p = skipParenGroup(stmt, p)
        if (p < 0) { ok = false; break }
        if (stmt[p]?.kind === 'comma') { p++; continue }
        ok = true
        break
      }
      if (!ok || stmt[p]?.kind !== 'word') {
        statements.push('UNKNOWN')
        continue
      }
      verb = stmt[p].text
      mainIdx = p
    }
    {
      let d = 0
      let prevWord = ''
      let sawInsert = verb === 'INSERT'
      for (let k = mainIdx; k < stmt.length; k++) {
        const tk = stmt[k]
        if (tk.kind === 'lparen') { d++; prevWord = '' }
        else if (tk.kind === 'rparen') { if (d > 0) d--; prevWord = '' }
        else if (d === 0 && tk.kind === 'word') {
          if (tk.text === 'INSERT') sawInsert = true
          if (prevWord === 'INSERT' && tk.text === 'OVERWRITE') hasOverwriteOrReplaceWhere = true
          if (sawInsert && prevWord === 'REPLACE' && tk.text === 'WHERE') hasOverwriteOrReplaceWhere = true
          if (prevWord === 'THEN' && tk.text === 'DELETE') hasMergeDelete = true
          prevWord = tk.text
        } else if (d === 0) {
          prevWord = ''
        }
      }
    }
    if (SQL_READ_VERBS.has(verb)) {
      let d = 0
      let hasMutatingTopLevel = false
      for (let k = mainIdx + 1; k < stmt.length; k++) {
        const tk = stmt[k]
        if (tk.kind === 'lparen') d++
        else if (tk.kind === 'rparen' && d > 0) d--
        else if (d === 0 && tk.kind === 'word' && k > 0 && stmt[k - 1]?.text !== 'AS') {
          if (tk.text === 'DELETE' || tk.text === 'DROP' || tk.text === 'TRUNCATE' || tk.text === 'MERGE' || tk.text === 'INSERT' || tk.text === 'UPDATE') {
            hasMutatingTopLevel = true
            verb = tk.text
            break
          }
        }
      }
      if (hasMutatingTopLevel) {
        statements.push(verb)
        continue
      }
    }
    const normalizedVerb = (SQL_READ_VERBS.has(verb) || SQL_WRITE_VERBS.has(verb) || SQL_DDL_VERBS.has(verb)) ? verb : 'UNKNOWN'
    statements.push(normalizedVerb)
  }

  const hasDropOrTruncate = hasOverwriteOrReplaceWhere || statements.some(v => v === 'DROP' || v === 'TRUNCATE')
  const hasDelete = hasMergeDelete || statements.some(v => v === 'DELETE')
  const hasUnknownStatement = statements.some(v => v === 'UNKNOWN')

  const base = (sqlClass: SqlClassification['sqlClass']): SqlClassification => {
    const out: SqlClassification = {
      sqlClass,
      statements: statements.slice(0, 16),
      hasDropOrTruncate: sqlClass === 'read' ? false : hasDropOrTruncate,
      hasDelete: sqlClass === 'read' ? false : hasDelete,
    }
    if (sqlClass !== 'read') {
      if (hasMergeDelete) out.hasMergeDelete = true
      if (hasUnknownStatement) out.hasUnknownStatement = true
      if (ambiguous) out.ambiguous = true
    }
    return out
  }

  if (!statements.length || ambiguous) return base('unknown')
  if (statements.some(v => SQL_DDL_VERBS.has(v))) return base('ddl')
  if (statements.some(v => SQL_WRITE_VERBS.has(v))) return base('write')
  if (statements.every(v => SQL_READ_VERBS.has(v))) return base('read')
  return base('unknown')
}

export function isValidEmailDomain(s: string): boolean {
  if (!s.length || s.length > 253 || s.startsWith('.') || s.endsWith('.')) return false
  const lastDot = s.lastIndexOf('.')
  if (lastDot <= 0 || s.length - lastDot - 1 < 2) return false
  for (let i = lastDot + 1; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (!((c >= 65 && c <= 90) || (c >= 97 && c <= 122))) return false
  }
  let labelLen = 0
  let labelStart = 0
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c === 46) {
      if (labelLen === 0 || labelLen > 63 || s.charCodeAt(labelStart) === 45 || s.charCodeAt(i - 1) === 45) return false
      labelLen = 0
      labelStart = i + 1
      continue
    }
    const ok = (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 45
    if (!ok) return false
    labelLen++
  }
  return labelLen > 0 && labelLen <= 63 && s.charCodeAt(labelStart) !== 45 && s.charCodeAt(s.length - 1) !== 45
}

function keyedCI(obj: Record<string, unknown>, lowerKey: string): unknown[] {
  const out: unknown[] = []
  for (const [k, v] of Object.entries(obj)) {
    if (k.toLowerCase() === lowerKey) out.push(v)
  }
  return out
}

const E1_ENDPOINTS = new Set(['formservice', 'batchformservice', 'appstack', 'dataservice', 'orchestrator', 'file', 'tokenrequest', 'discover', 'defaultconfig'])
const STRUCT_IDENT_RE = /^[A-Za-z][A-Za-z0-9_.-]{0,47}$/
const E1_CONTROL_ID_RE = /^[A-Za-z0-9_.-]{1,32}$/
const DBX_IDENT_RE = /^[A-Za-z0-9_.-]{1,64}$/

function validateStructuralIdent(val: unknown, pattern: RegExp, allowNumeric = false): string | undefined {
  if (typeof val !== 'string' || !val || !pattern.test(val) || isSensitiveValue(val)) return undefined
  if (!allowNumeric && isDataLikeKey(val)) return undefined
  return val
}

export type ExtractInput = {
  url: URL
  sanitizedPath: string
  method: string
  effectiveMethod: string
  kind: 'http' | 'upgrade'
  surface?: 'browser' | 'api'
  connectionType?: 'graph' | 'databricks' | 'service'
  mailRecipients?: { domains: string[]; count: number; complete: boolean; attachmentCount?: number }
  fileExists?: boolean
  hdr?: Record<string, string>
  rawHeaders: Record<string, string | string[] | undefined>
  reqType?: string
  decodedBuf?: Buffer
  bodyComplete: boolean
  transport: 'complete' | 'truncated' | 'not-read'
  transportReasons?: string[]
  isWrite: boolean
  isLive?: boolean
}

export type ExtractOutput = {
  actions: SemanticAction[]
  bodyShape?: Record<string, string>
  dupKeys?: true
  completeness: Completeness
  decodeComplete: boolean
}

export function extractSemantic(input: ExtractInput): ExtractOutput {
  const reasons: string[] = [...(input.transportReasons ?? [])]

  if (input.kind === 'upgrade') {
    return {
      actions: [{ family: 'upgrade', op: 'upgrade:websocket', resource: input.sanitizedPath, coverage: 'complete' }],
      completeness: { transport: 'not-read', decode: 'none', extract: 'complete', reasons: reasons.length ? reasons : undefined },
      decodeComplete: true,
    }
  }

  const decodedPathInfo = decodePathSegmentsStrict(input.url.pathname)
  if (input.isWrite && decodedPathInfo.invalidEncoding) {
    return {
      actions: [{
        family: input.connectionType ?? (input.surface === 'api' ? 'api' : 'rest'),
        op: 'ambiguous_path_encoding',
        resource: input.sanitizedPath,
        coverage: 'unknown',
      }],
      completeness: {
        transport: input.transport,
        decode: input.decodedBuf?.length ? (input.bodyComplete ? 'complete' : 'truncated') : 'none',
        extract: 'opaque',
        reasons: [...reasons, 'ambiguous-path-encoding'],
      },
      decodeComplete: input.bodyComplete,
    }
  }

  const isDatabricksSqlSubmit =
    input.isWrite &&
    (input.connectionType === 'databricks' || (input.surface === 'api' && input.url.hostname.toLowerCase().endsWith('.azuredatabricks.net'))) &&
    input.url.pathname.toLowerCase().replace(/\/+$/, '') === '/api/2.0/sql/statements'

  try {
    const rawBuf = input.decodedBuf ?? Buffer.alloc(0)
    const decodeStatus: Completeness['decode'] = rawBuf.length ? (input.bodyComplete ? 'complete' : 'truncated') : 'none'
    const decodeComplete = input.bodyComplete
    if (input.isLive && !reasons.includes('live')) reasons.push('live')

    const hasBody = rawBuf.length > 0
    let isBinary = false
    let decodedText: string | undefined
    if (hasBody) {
      if (isBinaryContentType(input.reqType) || hasBinaryMagic(rawBuf)) {
        isBinary = true
        reasons.push(input.reqType === 'multipart/form-data' ? 'multipart' : 'binary')
      } else {
        const text = decodeUtf8Prefix(rawBuf, !input.bodyComplete)
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
        bodyShape = buildBodyShape(parsedJson)
      } else if (decodedText !== undefined && input.reqType === 'application/x-www-form-urlencoded') {
        bodyShape = buildFormBodyShape(decodedText)
      }
    }

    const fullyIntact = input.bodyComplete && !dupKeys
    const defaultCov: SemanticAction['coverage'] = fullyIntact ? 'complete' : 'partial'
    const lowerPath = input.url.pathname.toLowerCase()
    const decodedLowerPath = decodedPathInfo.decodedPath.toLowerCase()
    const actions: SemanticAction[] = []
    let extractStatus: Completeness['extract'] = 'none'
    const obj = isJson && isPlainRecord(parsedJson) ? parsedJson : undefined

    const surface: 'browser' | 'api' = input.surface ?? 'browser'
    const makeTargetDigest = (resourceId?: string, bodySelector?: string, connTypeOverride?: string) =>
      computeTargetDigest({
        surface,
        connectionType: connTypeOverride !== undefined ? connTypeOverride : input.connectionType,
        host: input.url.hostname,
        port: input.url.port,
        scheme: input.url.protocol.replace(/:$/, ''),
        rawPathname: input.url.pathname,
        rawSearch: input.url.search,
        resourceId,
        bodySelector,
      })

    const isGraphHost = input.url.hostname.toLowerCase() === 'graph.microsoft.com'
    const isGraph = input.connectionType === 'graph' || (input.surface === 'api' && isGraphHost)
    const isDatabricks = input.connectionType === 'databricks' || (input.surface === 'api' && input.url.hostname.toLowerCase().endsWith('.azuredatabricks.net'))
    const isService = input.connectionType === 'service'
    const isGraphApiPath = isGraphHost && (decodedLowerPath.startsWith('/v1.0/') || decodedLowerPath.startsWith('/beta/'))
    const isSharePointRoute = !isGraphApiPath && (decodedLowerPath.includes('/_api/') || decodedLowerPath.includes('/_vti_bin/'))
    const spRestPath = extractSharePointRestSubpath(decodedLowerPath)
    const spDestructiveOp = spRestPath !== '' && /\/(?:recycle|recyclewithparameters|deleteobject|deletebyids?|deleteall|deleteallsecondstageitems|deletewithparameters)(?:\(|$|\/)/i.test(spRestPath)
    const isDeleteByIdsPath = spRestPath !== '' && /\/deletebyids(?:\(|$|\/)/i.test(spRestPath)
    const isSpBatchPath = /(?:^|\/)(?:_api|_vti_bin)(?:\/[^/]*)?\/\$batch\/?$/i.test(decodedLowerPath)

    if (isSharePointRoute) {
      const spResource = extractSharePointRestSubpath(input.sanitizedPath) || input.sanitizedPath
      const hasIfMatch = hasStrongIfMatch(input.rawHeaders)
      if (isDeleteByIdsPath) bodyShape = undefined
      if (isSpBatchPath) {
        actions.push({
          family: 'sharepoint',
          op: 'sharepoint:batch',
          resource: spResource,
          details: {
            hasRequestDigest: Boolean(input.rawHeaders['x-requestdigest']),
            hasIfMatch,
            targetDigest: input.isWrite ? makeTargetDigest(undefined, undefined, 'sharepoint') : undefined,
          },
          coverage: 'opaque-batch',
        })
        extractStatus = 'opaque'
      } else {
        let bodySelector: string | undefined
        let selectedIdCount: number | undefined
        let bodySelectionIncomplete = false
        if (isDeleteByIdsPath && input.isWrite) {
          if (!fullyIntact || !obj) {
            bodySelectionIncomplete = true
          } else {
            const idMatches = keyedCI(obj, 'ids')
            const allowedMetaKeys = new Set(['__metadata', '@odata.type'])
            const extraKeys = Object.keys(obj).filter(k => k.toLowerCase() !== 'ids' && !allowedMetaKeys.has(k.toLowerCase()))
            if (idMatches.length !== 1 || extraKeys.length > 0) {
              bodySelectionIncomplete = true
            } else {
              const parsed = validateSharePointDeleteIds(idMatches[0])
              if (!parsed.ok) bodySelectionIncomplete = true
              else {
                selectedIdCount = parsed.ids.length
                bodySelector = parsed.bodySelector
              }
            }
          }
        }
        const details: Record<string, unknown> = {
          hasIfMatch,
          hasRequestDigest: Boolean(input.rawHeaders['x-requestdigest']),
          destructiveAction: spDestructiveOp || undefined,
          bodySelectionIncomplete: bodySelectionIncomplete || undefined,
          selectedIdCount,
          targetDigest: input.isWrite && !bodySelectionIncomplete ? makeTargetDigest(undefined, bodySelector, 'sharepoint') : undefined,
          override: input.hdr?.['x-http-method'],
        }
        if (!isDeleteByIdsPath) {
          const rawMetaType = (obj?.__metadata as Record<string, unknown> | undefined)?.type ?? obj?.['@odata.type']
          details.metadataType = validateStructuralIdent(rawMetaType, /^[#A-Za-z][A-Za-z0-9_.-]{0,63}$/)
        }
        actions.push({
          family: 'sharepoint',
          op: spDestructiveOp ? 'sharepoint:delete' : `sharepoint:${input.effectiveMethod}`,
          resource: spResource,
          details,
          coverage: bodySelectionIncomplete ? 'unknown' : defaultCov,
        })
        extractStatus = bodySelectionIncomplete ? 'opaque' : fullyIntact ? 'complete' : 'partial'
      }
    } else if (isGraph) {
      const segs = lowerPath.replace(/^\/(?:v1\.0|beta)\//, '').split('/').filter(Boolean)
      const segCollections = segs.map(s => {
        let dec = s
        try { dec = decodeURIComponent(s) } catch {}
        return dec.toLowerCase().replace(/\(.*$/, '')
      })
      const lastSeg = (segCollections.at(-1) ?? '').split('.').pop() ?? ''
      const hasIfMatch = hasStrongIfMatch(input.rawHeaders)
      const eff = input.effectiveMethod

      if (input.isWrite && ['sendmail', 'send', 'reply', 'replyall', 'forward'].includes(lastSeg)) {
        const recips = input.mailRecipients ?? { domains: [], count: 0, complete: false }
        const opName = lastSeg === 'sendmail' ? 'sendMail' : lastSeg === 'replyall' ? 'replyAll' : lastSeg
        actions.push({
          family: 'graph',
          op: `graph:${opName}`,
          resource: input.sanitizedPath,
          details: {
            recipientDomains: recips.domains,
            recipientCount: recips.count,
            recipientsComplete: recips.complete,
            attachmentCount: recips.attachmentCount,
            targetDigest: makeTargetDigest(),
          },
          coverage: defaultCov,
        })
        extractStatus = fullyIntact ? 'complete' : 'partial'
      } else if (input.isWrite && eff === 'POST' && lastSeg === 'createuploadsession') {
        actions.push({
          family: 'graph',
          op: 'graph:upload_session',
          resource: input.sanitizedPath,
          details: { targetDigest: makeTargetDigest() },
          coverage: defaultCov,
        })
        extractStatus = fullyIntact ? 'complete' : 'partial'
      } else if (input.isWrite && eff === 'POST' && lastSeg === 'messages' && (segCollections.includes('chats') || segCollections.includes('channels'))) {
        actions.push({
          family: 'graph',
          op: 'graph:teams_message',
          resource: input.sanitizedPath,
          details: { fieldCount: bodyShape ? Object.keys(bodyShape).length : undefined, targetDigest: makeTargetDigest() },
          coverage: defaultCov,
        })
        extractStatus = fullyIntact ? 'complete' : 'partial'
      } else if (input.isWrite && eff === 'POST' && lastSeg === 'messages') {
        actions.push({
          family: 'graph',
          op: 'graph:draft',
          resource: input.sanitizedPath,
          details: { targetDigest: makeTargetDigest() },
          coverage: defaultCov,
        })
        extractStatus = fullyIntact ? 'complete' : 'partial'
      } else if (input.isWrite && (segCollections.includes('messages') || segCollections.includes('mailfolders')) && (eff === 'PATCH' || lastSeg === 'move')) {
        const fields = obj ? Object.keys(obj).slice(0, 32).map(scrubStructuralKey) : []
        actions.push({
          family: 'graph',
          op: 'graph:mail_patch',
          resource: input.sanitizedPath,
          details: { fields: fields.length ? fields : undefined, hasIfMatch, targetDigest: makeTargetDigest() },
          coverage: defaultCov,
        })
        extractStatus = fullyIntact ? 'complete' : 'partial'
      } else if (input.isWrite && segCollections.includes('workbook')) {
        actions.push({
          family: 'graph',
          op: 'graph:excel_write',
          resource: input.sanitizedPath,
          details: { method: eff, hasIfMatch, targetDigest: makeTargetDigest() },
          coverage: defaultCov,
        })
        extractStatus = fullyIntact ? 'complete' : 'partial'
      } else if (input.isWrite && eff === 'PUT' && lastSeg === 'content') {
        actions.push({
          family: 'graph',
          op: 'graph:file_write',
          resource: input.sanitizedPath,
          details: {
            hasIfMatch,
            hasIfNoneMatchStar: hasIfNoneMatchStar(input.rawHeaders) || undefined,
            newFile: input.fileExists === false ? true : undefined,
            targetDigest: makeTargetDigest(),
          },
          coverage: isBinary || input.transport === 'truncated' ? 'complete' : defaultCov,
        })
        extractStatus = 'complete'
      } else if (
        input.isWrite &&
        (eff === 'DELETE' || input.method === 'DELETE' || lastSeg === 'permanentdelete') &&
        (segCollections.includes('drives') || segCollections.includes('drive') || segCollections.includes('items') || segCollections.includes('shares') || segCollections.includes('messages') || segCollections.includes('mailfolders'))
      ) {
        actions.push({
          family: 'graph',
          op: 'graph:file_delete',
          resource: input.sanitizedPath,
          details: {
            hasIfMatch,
            targetDigest: makeTargetDigest(),
            permanentDelete: lastSeg === 'permanentdelete' ? true : undefined,
          },
          coverage: defaultCov,
        })
        extractStatus = fullyIntact ? 'complete' : 'partial'
      } else if (input.isWrite) {
        actions.push({
          family: 'graph',
          op: `graph:${eff}`,
          resource: input.sanitizedPath,
          details: { hasIfMatch, targetDigest: makeTargetDigest() },
          coverage: isBinary || structuredJsonParseFailed ? 'partial' : defaultCov,
        })
        extractStatus = isBinary || structuredJsonParseFailed ? 'opaque' : fullyIntact ? 'complete' : 'partial'
      } else {
        actions.push({ family: 'graph', op: `graph:${eff}`, resource: input.sanitizedPath, coverage: 'complete' })
        extractStatus = 'complete'
      }
    } else if (isDatabricks) {
      const cleanPath = lowerPath.replace(/\/$/, '')
      if (cleanPath === '/api/2.0/sql/statements' && (input.method === 'POST' || input.effectiveMethod === 'POST')) {
        const stmtRaw = typeof obj?.statement === 'string' ? obj.statement : undefined
        const stmtTrimmed = stmtRaw?.trim() ?? ''
        const cls: SqlClassification = stmtTrimmed
          ? classifySqlStatement(stmtRaw!)
          : { sqlClass: 'unknown', statements: [], hasDropOrTruncate: false, hasDelete: false }
        const uninspectableSql =
          !stmtTrimmed ||
          structuredJsonParseFailed ||
          !fullyIntact ||
          isBinary ||
          cls.ambiguous === true ||
          cls.hasUnknownStatement === true ||
          cls.sqlClass === 'unknown'
        const wh = validateStructuralIdent(obj?.warehouse_id, DBX_IDENT_RE, true)
        const cat = validateStructuralIdent(obj?.catalog, DBX_IDENT_RE)
        const sch = validateStructuralIdent(obj?.schema, DBX_IDENT_RE)
        const details: Record<string, unknown> = {
          sqlClass: cls.sqlClass,
          statements: cls.statements,
          hasDropOrTruncate: cls.hasDropOrTruncate || undefined,
          hasDelete: cls.hasDelete || undefined,
          hasMergeDelete: cls.hasMergeDelete || undefined,
          hasUnknownStatement: cls.hasUnknownStatement || undefined,
          ambiguous: cls.ambiguous || undefined,
          uninspectable: uninspectableSql || undefined,
          warehouseId: wh,
          catalog: cat,
          schema: sch,
          parameterCount: Array.isArray(obj?.parameters) && obj.parameters.length > 0 ? obj.parameters.length : undefined,
        }
        if (stmtRaw && cls.sqlClass !== 'read' && !cls.hasDropOrTruncate && !cls.hasMergeDelete && !uninspectableSql) {
          details.sqlContextDigest = computeSqlContextDigest({
            sql: stmtRaw,
            parameters: obj && 'parameters' in obj ? obj.parameters : undefined,
            warehouseId: typeof obj?.warehouse_id === 'string' ? obj.warehouse_id : undefined,
            catalog: typeof obj?.catalog === 'string' ? obj.catalog : undefined,
            schema: typeof obj?.schema === 'string' ? obj.schema : undefined,
          })
        }
        actions.push({
          family: 'databricks',
          op: `databricks:sql_${cls.sqlClass}`,
          resource: wh ?? input.sanitizedPath,
          details,
          coverage: stmtRaw && fullyIntact ? 'complete' : 'partial',
        })
        extractStatus = stmtRaw && fullyIntact ? 'complete' : 'partial'
      } else if (cleanPath.startsWith('/api/2.0/sql/statements/') && cleanPath.endsWith('/cancel')) {
        actions.push({ family: 'databricks', op: 'databricks:sql_cancel', resource: input.sanitizedPath, coverage: 'complete' })
        extractStatus = 'complete'
      } else if (cleanPath.startsWith('/api/2.0/sql/statements/')) {
        actions.push({ family: 'databricks', op: 'databricks:sql_status', resource: input.sanitizedPath, coverage: 'complete' })
        extractStatus = 'complete'
      } else if (cleanPath.startsWith('/api/2.1/unity-catalog/')) {
        actions.push({
          family: 'databricks',
          op: `databricks:unity_catalog_${input.effectiveMethod}`,
          resource: input.sanitizedPath,
          details: input.isWrite ? { targetDigest: makeTargetDigest() } : undefined,
          coverage: defaultCov,
        })
        extractStatus = fullyIntact ? 'complete' : 'partial'
      } else {
        actions.push({
          family: 'databricks',
          op: `databricks:${input.effectiveMethod}`,
          resource: input.sanitizedPath,
          details: input.isWrite ? { targetDigest: makeTargetDigest() } : undefined,
          coverage: defaultCov,
        })
        extractStatus = fullyIntact ? 'complete' : 'partial'
      }
    } else if (decodedLowerPath.includes('/jderest/')) {
      const m = /\/jderest\/(?:v\d+\/)?([^/;?]+)/i.exec(decodedPathInfo.decodedPath)
      const rawEndpoint = m ? m[1].toLowerCase() : 'ais'
      const endpoint = E1_ENDPOINTS.has(rawEndpoint) ? rawEndpoint : 'ais'

      let malformedE1Action = false
      let conflictingActions = false
      let unattributedMutation = false
      let hasMutatingFormAction = false
      const mutatingForms = new Set<string>()
      const allFormNames: string[] = []
      const scalarActionValues: string[] = []
      const allRawActions: unknown[] = []
      let sawFormActionsField = false

      const inspectE1Unit = (unit: Record<string, unknown>): boolean => {
        const containers: Record<string, unknown>[] = [unit]
        for (const subKey of ['actionRequest', 'formRequest'] as const) {
          if (subKey in unit && unit[subKey] !== undefined) {
            if (isPlainRecord(unit[subKey])) containers.push(unit[subKey] as Record<string, unknown>)
            else malformedE1Action = true
          }
        }
        let hasUsableField = false
        const unitFormNames: string[] = []
        for (const c of containers) {
          for (const fk of ['formName', 'targetName'] as const) {
            if (fk in c && c[fk] !== undefined && c[fk] !== null) {
              if (typeof c[fk] === 'string' && (c[fk] as string).trim()) {
                const ident = validateStructuralIdent(c[fk], STRUCT_IDENT_RE)
                if (ident) { unitFormNames.push(ident); hasUsableField = true }
                else malformedE1Action = true
              } else {
                malformedE1Action = true
              }
            }
          }
        }
        const uniqueUnitForms = [...new Set(unitFormNames)]
        if (uniqueUnitForms.length > 1) malformedE1Action = true
        const unitForm = uniqueUnitForms.length === 1 ? uniqueUnitForms[0] : undefined
        if (unitForm) allFormNames.push(unitForm)

        const unitScalars: string[] = []
        for (const c of containers) {
          for (const k of ['action', 'formServiceAction'] as const) {
            if (k in c && c[k] !== undefined && c[k] !== null) {
              if (typeof c[k] === 'string' && (c[k] as string).trim()) {
                const v = (c[k] as string).trim()
                unitScalars.push(v)
                scalarActionValues.push(v)
                hasUsableField = true
              } else {
                malformedE1Action = true
              }
            }
          }
        }
        if (new Set(unitScalars.map(s => s.toUpperCase())).size > 1) conflictingActions = true
        let unitMutates = unitScalars.some(s => ['W', 'C', 'U', 'D'].includes(s.toUpperCase()))

        for (const c of containers) {
          if ('formActions' in c && c.formActions !== undefined) {
            sawFormActionsField = true
            if (Array.isArray(c.formActions)) {
              for (const a of c.formActions) {
                allRawActions.push(a)
                if (!isPlainRecord(a)) { malformedE1Action = true; continue }
                const cmd = a.command
                if (typeof cmd !== 'string' || !cmd.trim()) { malformedE1Action = true; continue }
                hasUsableField = true
                if (E1_MUTATING_FORM_COMMANDS.has(cmd.toLowerCase())) {
                  unitMutates = true
                  hasMutatingFormAction = true
                }
              }
            } else {
              malformedE1Action = true
            }
          }
          if (typeof c.dataServiceType === 'string' && c.dataServiceType.trim()) hasUsableField = true
          if ((typeof c.findOnEntry === 'string' && c.findOnEntry.trim()) || typeof c.findOnEntry === 'boolean') hasUsableField = true
          if (typeof c.returnControlIDs === 'string' && c.returnControlIDs.trim()) hasUsableField = true
          if (
            (typeof c.maxPageSize === 'string' && c.maxPageSize.trim()) ||
            (typeof c.maxPageSize === 'number' && Number.isFinite(c.maxPageSize))
          ) {
            hasUsableField = true
          }
        }
        if (unitMutates) {
          if (unitForm) mutatingForms.add(unitForm)
          else unattributedMutation = true
        }
        return hasUsableField
      }

      if (obj) {
        const rootUsable = inspectE1Unit(obj)
        if (input.isWrite && (endpoint === 'formservice' || endpoint === 'dataservice') && !rootUsable) {
          malformedE1Action = true
        }
        if ('formRequests' in obj && obj.formRequests !== undefined) {
          if (Array.isArray(obj.formRequests) && obj.formRequests.length > 0) {
            for (const item of obj.formRequests) {
              if (!isPlainRecord(item) || !inspectE1Unit(item)) malformedE1Action = true
            }
          } else {
            malformedE1Action = true
          }
        } else if (endpoint === 'batchformservice' && input.isWrite) {
          malformedE1Action = true
        }
      } else if (
        parsedJson !== undefined ||
        structuredJsonParseFailed ||
        (input.isWrite && (endpoint === 'formservice' || endpoint === 'batchformservice' || endpoint === 'dataservice'))
      ) {
        malformedE1Action = true
      }

      const primaryForm = [...new Set(allFormNames)][0]
      const mutatingScalar = scalarActionValues.find(s => ['W', 'C', 'U', 'D'].includes(s.toUpperCase()))
      const actIdent = validateStructuralIdent(mutatingScalar ?? scalarActionValues[0], /^[A-Za-z][A-Za-z0-9_-]{0,23}$/)
      const formActions = sawFormActionsField
        ? allRawActions.slice(0, 32).map(a => {
            if (!isPlainRecord(a)) return { command: 'unknown' }
            return {
              command: validateStructuralIdent(a.command, STRUCT_IDENT_RE),
              controlID: validateStructuralIdent(a.controlID, E1_CONTROL_ID_RE, true),
            }
          })
        : undefined
      const details: Record<string, unknown> = {
        formName: primaryForm,
        mutatingForms: mutatingForms.size > 0 ? [...mutatingForms].sort() : undefined,
        unattributedMutation: unattributedMutation || undefined,
        version: validateStructuralIdent(obj?.version, STRUCT_IDENT_RE),
        action: actIdent,
        conflictingActions: conflictingActions || undefined,
        targetType: validateStructuralIdent(obj?.targetType, STRUCT_IDENT_RE),
        dataServiceType: validateStructuralIdent(obj?.dataServiceType, STRUCT_IDENT_RE),
        hasMutatingFormAction: sawFormActionsField && hasMutatingFormAction ? true : undefined,
        formActions,
        formActionsTruncated: sawFormActionsField && allRawActions.length > 32 ? true : undefined,
        malformedE1Action: malformedE1Action || undefined,
        targetDigest: input.isWrite ? makeTargetDigest(primaryForm) : undefined,
      }
      actions.push({
        family: 'e1-ais',
        op: actIdent ? `${endpoint}:${actIdent}` : `${endpoint}:${input.effectiveMethod}`,
        resource: primaryForm ?? input.sanitizedPath,
        details,
        coverage: defaultCov,
      })
      extractStatus = fullyIntact ? 'complete' : 'partial'
    } else if (isService) {
      actions.push({
        family: 'service',
        op: `service:${input.effectiveMethod}`,
        resource: input.sanitizedPath,
        details: {
          hasIfMatch: hasStrongIfMatch(input.rawHeaders) || undefined,
          targetDigest: input.isWrite ? makeTargetDigest() : undefined,
        },
        coverage: isBinary || structuredJsonParseFailed ? 'partial' : defaultCov,
      })
      extractStatus = isBinary || structuredJsonParseFailed ? 'opaque' : fullyIntact ? 'complete' : 'partial'
    } else if (input.isWrite) {
      actions.push({
        family: input.surface === 'api' ? 'api' : 'rest',
        op: `${input.surface === 'api' ? 'api' : 'rest'}:${input.effectiveMethod}`,
        resource: input.sanitizedPath,
        details: { targetDigest: makeTargetDigest() },
        coverage: isBinary || structuredJsonParseFailed ? 'partial' : defaultCov,
      })
      extractStatus = isBinary || structuredJsonParseFailed ? 'opaque' : fullyIntact ? 'complete' : 'partial'
    }

    return {
      actions,
      bodyShape: bodyShape && Object.keys(bodyShape).length > 0 ? bodyShape : undefined,
      dupKeys: dupKeys ? true : undefined,
      completeness: {
        transport: input.transport,
        decode: decodeStatus,
        extract: extractStatus,
        reasons: reasons.length > 0 ? reasons : undefined,
      },
      decodeComplete,
    }
  } catch {
    return {
      actions: isDatabricksSqlSubmit
        ? [{ family: 'databricks', op: 'databricks:sql_unknown', resource: input.sanitizedPath, details: { sqlClass: 'unknown', uninspectable: true }, coverage: 'unknown' }]
        : input.isWrite
          ? [{ family: input.surface === 'api' ? 'api' : 'rest', op: `${input.surface === 'api' ? 'api' : 'rest'}:${input.effectiveMethod}`, resource: input.sanitizedPath, coverage: 'unknown' }]
          : [],
      completeness: {
        transport: input.transport,
        decode: 'none',
        extract: 'none',
        reasons: [...reasons, 'extractor-error'],
      },
      decodeComplete: false,
    }
  }
}
