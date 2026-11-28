export const REDACT_V = 1
export const REDACTED = '[REDACTED]'
export const REDACTED_SEG = '[REDACTED:seg]'

const ENTIRE_KEY_ONLY = new Set(['auth', 'authorization', 'key', 'session', 'pin', 'pass', 'sig', 'code'])
const CRED_SUFFIX = new Set(['code', 'key', 'pin', 'pass'])
const SENSITIVE_MODIFIER = new Set([
  'auth', 'verify', 'verification', 'security', 'sms', 'otp', 'mfa', 'one', 'time',
  'reset', 'confirm', 'session', 'secret', 'signing', 'encryption', 'master',
  'private', 'access', 'api', 'client', 'pass', 'pin', 'user',
])
const SUFFIX_COMPOUNDS = [
  'client_secret', 'access_token', 'id_token', 'refresh_token', 'session_id',
  'auth_token', 'jas_token', 'form_digest_value', 'request_digest', 'code_verifier',
]
const UNAMBIGUOUS_TOKENS = new Set([
  'password', 'passwd', 'pwd', 'passcode', 'passphrase', 'secret', 'token',
  'cookie', 'cookies', 'credential', 'credentials', 'bearer', 'jwt', 'assertion',
  'saml', 'xsrf', 'csrf', 'otp', 'mfa', 'totp', 'cvv', 'cvc', 'ssn', 'iban',
  'oauth', 'jasserver',
])
const SENSITIVE_CONTAINERS = new Set(['credentials', 'cookies', 'tokens', 'secrets'])

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}(?:[T\s]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/i
const NUMERIC_RE = /^[+-]?\d+(?:\.\d+)?$/
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const BASE64_HEX_RE = /^[A-Za-z0-9+/=_-]+$/

export const SECRET_PATTERNS: RegExp[] = [
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  /\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=._-]{8,}/gi,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
  /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  /\bAIza[0-9A-Za-z_-]{30,}\b/g,
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g,
  /((?:^|[?&])sig=)[A-Za-z0-9%+/=]{20,}/gi,
]

export const SINGLE_SECRET_PATTERNS: RegExp[] = SECRET_PATTERNS.map(
  re => new RegExp(re.source, re.flags.replace('g', '')),
)

export function shannonEntropy(s: string): number {
  if (!s.length) return 0
  const freq = new Map<string, number>()
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]
    freq.set(ch, (freq.get(ch) ?? 0) + 1)
  }
  let h = 0
  const len = s.length
  for (const count of freq.values()) {
    const p = count / len
    h -= p * Math.log2(p)
  }
  return h
}

export function isTokenShaped(value: string): boolean {
  if (typeof value !== 'string' || value.length < 16) return false
  if (NUMERIC_RE.test(value) || UUID_RE.test(value) || ISO_DATE_RE.test(value) || /^https?:\/\//i.test(value)) return false
  return shannonEntropy(value) >= 3.5
}

export function safeDecodeURIComponent(s: string): string {
  try {
    return decodeURIComponent(s)
  } catch {
    return s.replace(/%([0-9a-fA-F]{2})/g, (m, hex) => {
      const code = parseInt(hex, 16)
      return code < 128 ? String.fromCharCode(code) : m
    })
  }
}

const isAsciiUpper = (c: number) => c >= 65 && c <= 90
const isAsciiLower = (c: number) => c >= 97 && c <= 122
const isAsciiDigit = (c: number) => c >= 48 && c <= 57
const isAsciiAlnum = (c: number) => isAsciiUpper(c) || isAsciiLower(c) || isAsciiDigit(c)

function tokenizeAsciiLinear(s: string): string[] {
  const tokens: string[] = []
  const len = s.length
  let tokStart = -1
  for (let i = 0; i < len; i++) {
    const c = s.charCodeAt(i)
    if (!isAsciiAlnum(c)) {
      if (tokStart >= 0) {
        tokens.push(s.slice(tokStart, i).toLowerCase())
        tokStart = -1
      }
      continue
    }
    if (tokStart < 0) {
      tokStart = i
      continue
    }
    if (isAsciiUpper(c)) {
      const prev = s.charCodeAt(i - 1)
      if (
        isAsciiLower(prev) ||
        isAsciiDigit(prev) ||
        (isAsciiUpper(prev) && i + 1 < len && isAsciiLower(s.charCodeAt(i + 1)))
      ) {
        tokens.push(s.slice(tokStart, i).toLowerCase())
        tokStart = i
      }
    }
  }
  if (tokStart >= 0) tokens.push(s.slice(tokStart).toLowerCase())
  return tokens
}

// Single-pass identifier tokenizer: NFKC-normalize then split on non-alphanumerics and camelCase/acronym boundaries.
export function tokenizeKey(key: string): string[] {
  return tokenizeAsciiLinear(key.normalize('NFKC'))
}

function isSensitiveTokens(tokens: string[]): boolean {
  if (!tokens.length) return false
  if (tokens.length === 1 && ENTIRE_KEY_ONLY.has(tokens[0])) return true
  const last = tokens[tokens.length - 1]
  if (tokens.length >= 2 && CRED_SUFFIX.has(last) && tokens.slice(0, -1).some(t => SENSITIVE_MODIFIER.has(t))) {
    return true
  }
  const joined = tokens.join('_')
  for (const suffix of SUFFIX_COMPOUNDS) {
    if (joined === suffix || joined.endsWith('_' + suffix)) return true
  }
  return tokens.some(t => UNAMBIGUOUS_TOKENS.has(t))
}

export function isSensitiveContainerKey(key: string): boolean {
  const norm = key.normalize('NFKC')
  if (SENSITIVE_CONTAINERS.has(norm.toLowerCase())) return true
  const tokens = tokenizeAsciiLinear(norm)
  return tokens.length === 1 && SENSITIVE_CONTAINERS.has(tokens[0])
}

export function isSensitiveKey(key: string): boolean {
  return isSensitiveTokens(tokenizeKey(key))
}

export function isSensitiveValue(s: string): boolean {
  if (!s) return false
  for (const re of SINGLE_SECRET_PATTERNS) {
    if (re.test(s)) return true
  }
  return (
    s.length >= 32 &&
    BASE64_HEX_RE.test(s) &&
    !UUID_RE.test(s) &&
    !ISO_DATE_RE.test(s) &&
    !NUMERIC_RE.test(s) &&
    shannonEntropy(s) >= 4.0
  )
}

export function scrubText(input: string): { text: string } {
  if (!input) return { text: input }
  let text = input
  for (const re of SECRET_PATTERNS) {
    re.lastIndex = 0
    text = text.replace(re, (m, g1) => (typeof g1 === 'string' && m.startsWith(g1) ? `${g1}${REDACTED}` : REDACTED))
  }
  return { text }
}

// Single-pass JSON scanner for duplicate keys within any object, honoring JSON string escapes.
export function scanJsonDuplicateKeys(text: string): boolean {
  const len = text.length
  let i = 0
  type Frame = { type: '{'; keys: Set<string>; expectKey: boolean } | { type: '[' }
  const stack: Frame[] = []

  const skipWs = () => {
    while (i < len) {
      const c = text.charCodeAt(i)
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++
      else break
    }
  }

  const readString = (): string | null => {
    if (text.charCodeAt(i) !== 0x22) return null
    const start = i
    i++
    let escaped = false
    while (i < len) {
      const c = text.charCodeAt(i)
      if (c === 0x5c) {
        escaped = true
        i += 2
        continue
      }
      if (c === 0x22) {
        i++
        const raw = text.slice(start, i)
        if (!escaped) return raw.slice(1, -1)
        try {
          return JSON.parse(raw)
        } catch {
          return raw.slice(1, -1)
        }
      }
      i++
    }
    return null
  }

  while (i < len) {
    skipWs()
    if (i >= len) break
    const ch = text[i]
    const top = stack[stack.length - 1]
    if (ch === '{') {
      if (top && top.type === '{') top.expectKey = false
      stack.push({ type: '{', keys: new Set(), expectKey: true })
      i++
    } else if (ch === '}') {
      stack.pop()
      i++
    } else if (ch === '[') {
      if (top && top.type === '{') top.expectKey = false
      stack.push({ type: '[' })
      i++
    } else if (ch === ']') {
      stack.pop()
      i++
    } else if (ch === ':') {
      if (top && top.type === '{') top.expectKey = false
      i++
    } else if (ch === ',') {
      if (top && top.type === '{') top.expectKey = true
      i++
    } else if (ch === '"') {
      const str = readString()
      if (str === null) return false
      if (top && top.type === '{' && top.expectKey) {
        if (top.keys.has(str)) return true
        top.keys.add(str)
        top.expectKey = false
      }
    } else {
      if (top && top.type === '{') top.expectKey = false
      while (i < len) {
        const c = text[i]
        if (c === ',' || c === '}' || c === ']' || c === ' ' || c === '\t' || c === '\r' || c === '\n') break
        i++
      }
    }
  }
  return false
}

export function parseJsonSafe(text: string): { ok: true; value: unknown; dupKeys: boolean } | { ok: false } {
  const trimmed = text.trim()
  if (!trimmed) return { ok: false }
  const first = trimmed[0]
  if (first !== '{' && first !== '[' && first !== '"' && first !== '-' && !(first >= '0' && first <= '9') && first !== 't' && first !== 'f' && first !== 'n') {
    return { ok: false }
  }
  try {
    return { ok: true, value: JSON.parse(trimmed), dupKeys: scanJsonDuplicateKeys(trimmed) }
  } catch {
    return { ok: false }
  }
}

export function isDataLikeKey(key: string): boolean {
  if (!key) return false
  if (key.length > 32) return true
  if (EMAIL_RE.test(key) || UUID_RE.test(key) || NUMERIC_RE.test(key) || isSensitiveValue(key)) return true
  return key.length >= 20 && BASE64_HEX_RE.test(key) && shannonEntropy(key) >= 4.0
}

export function scrubStructuralKey(k: string): string {
  return isDataLikeKey(k) ? '<key>' : k
}

export function buildBodyShape(value: unknown, maxDepth = 6, maxPaths = 64): Record<string, string> {
  const shape: Record<string, string> = {}
  let count = 0

  const add = (path: string, type: string) => {
    if (path in shape) {
      if (shape[path] !== type) shape[path] = 'mixed'
      return
    }
    if (count >= maxPaths) return
    shape[path] = type
    count++
  }

  const scalarType = (v: unknown): string => (v === null ? 'null' : typeof v)

  const walk = (v: unknown, prefix: string, depth: number) => {
    if (count >= maxPaths) return
    if (v === null || typeof v !== 'object') {
      add(prefix || '$', scalarType(v))
      return
    }
    if (Array.isArray(v)) {
      const arrPath = prefix ? `${prefix}[]` : '[]'
      if (v.length === 0) {
        add(arrPath, 'empty')
        return
      }
      if (depth >= maxDepth) {
        add(arrPath, 'array')
        return
      }
      let hasObj = false
      const primTypes = new Set<string>()
      for (const el of v.slice(0, 16)) {
        if (el !== null && typeof el === 'object') {
          hasObj = true
          walk(el, arrPath, depth + 1)
        } else {
          primTypes.add(scalarType(el))
        }
      }
      if (primTypes.size > 0 && !hasObj) {
        add(arrPath, primTypes.size === 1 ? [...primTypes][0] : 'mixed')
      }
      return
    }
    const entries = Object.entries(v as Record<string, unknown>)
    if (entries.length === 0 || depth >= maxDepth) {
      add(prefix || '$', 'object')
      return
    }
    for (const [rawKey, child] of entries) {
      if (count >= maxPaths) break
      const k = scrubStructuralKey(rawKey)
      walk(child, prefix ? `${prefix}.${k}` : k, depth + 1)
    }
  }

  walk(value, '', 0)
  return shape
}

export type FormPair = { raw: string; rawKey: string; rawVal: string; key: string; val: string; hasEq: boolean }

// Single form-urlencoded / query-string walker shared by query sanitization and form body shape.
export function* pairs(raw: string): Generator<FormPair> {
  const q = raw.startsWith('?') ? raw.slice(1) : raw
  for (const part of q.split('&')) {
    const eq = part.indexOf('=')
    if (eq < 0) {
      const key = part ? safeDecodeURIComponent(part.replace(/\+/g, ' ')) : ''
      yield { raw: part, rawKey: part, rawVal: '', key, val: '', hasEq: false }
    } else {
      const rawKey = part.slice(0, eq)
      const rawVal = part.slice(eq + 1)
      yield {
        raw: part,
        rawKey,
        rawVal,
        key: safeDecodeURIComponent(rawKey.replace(/\+/g, ' ')),
        val: safeDecodeURIComponent(rawVal.replace(/\+/g, ' ')),
        hasEq: true,
      }
    }
  }
}

export function buildFormBodyShape(raw: string, maxPaths = 64): Record<string, string> {
  const shape: Record<string, string> = {}
  let count = 0
  for (const p of pairs(raw)) {
    if (!p.raw || count >= maxPaths) continue
    const k = scrubStructuralKey(p.key)
    const t = p.val === '' ? 'empty' : NUMERIC_RE.test(p.val) ? 'number' : (p.val === 'true' || p.val === 'false') ? 'boolean' : 'string'
    if (!(k in shape)) {
      shape[k] = t
      count++
    } else if (shape[k] !== t) {
      shape[k] = 'mixed'
    }
  }
  return shape
}

const isHighSurrogate = (code: number) => code >= 0xd800 && code <= 0xdbff
const isLowSurrogate = (code: number) => code >= 0xdc00 && code <= 0xdfff

// Strict UTF-8 byte-bounded head+tail truncation without splitting UTF-16 surrogates or %XX.
export function truncateUtf8HeadTail(str: string, maxBytes: number, headBytes?: number, tailBytes?: number): string {
  if (maxBytes <= 0) return ''
  if (Buffer.byteLength(str, 'utf8') <= maxBytes) return str
  const ellipsis = '…'
  const ellipsisBytes = 3
  if (maxBytes <= ellipsisBytes) return ''
  const avail = maxBytes - ellipsisBytes
  const targetHead = Math.min(headBytes ?? Math.floor(avail * 0.75), avail)
  const targetTail = Math.min(tailBytes ?? (avail - targetHead), avail - targetHead)

  let headEnd = 0
  let hBytes = 0
  while (headEnd < str.length) {
    const cp = str.codePointAt(headEnd)!
    const cuLen = cp > 0xffff ? 2 : 1
    const bLen = cp <= 0x7f ? 1 : cp <= 0x7ff ? 2 : cp <= 0xffff ? 3 : 4
    if (hBytes + bLen > targetHead) break
    hBytes += bLen
    headEnd += cuLen
  }
  if (headEnd >= 1 && str[headEnd - 1] === '%') headEnd -= 1
  else if (headEnd >= 2 && str[headEnd - 2] === '%' && /[0-9a-fA-F]/.test(str[headEnd - 1])) headEnd -= 2

  let tailStart = str.length
  let tBytes = 0
  while (tailStart > headEnd) {
    let prev = tailStart - 1
    if (prev > headEnd && isLowSurrogate(str.charCodeAt(prev)) && isHighSurrogate(str.charCodeAt(prev - 1))) {
      prev--
    }
    const cp = str.codePointAt(prev)!
    const bLen = cp <= 0x7f ? 1 : cp <= 0x7ff ? 2 : cp <= 0xffff ? 3 : 4
    if (tBytes + bLen > targetTail) break
    tBytes += bLen
    tailStart = prev
  }
  if (tailStart >= 1 && str[tailStart - 1] === '%') tailStart = Math.min(str.length, tailStart + 2)
  else if (tailStart >= 2 && str[tailStart - 2] === '%' && /[0-9a-fA-F]/.test(str[tailStart - 1])) tailStart = Math.min(str.length, tailStart + 1)

  if (tailStart <= headEnd) return str.slice(0, headEnd)
  return `${str.slice(0, headEnd)}${ellipsis}${str.slice(tailStart)}`
}

export function sanitizePath(pathname: string): string {
  return pathname.split('/').map(seg => {
    if (!seg || seg.includes('[REDACTED')) return seg
    const dec = safeDecodeURIComponent(seg)
    if (isSensitiveValue(dec)) return REDACTED_SEG
    if (
      dec.length >= 24 &&
      !UUID_RE.test(dec) &&
      !ISO_DATE_RE.test(dec) &&
      BASE64_HEX_RE.test(dec) &&
      shannonEntropy(dec) >= 4.0
    ) {
      return REDACTED_SEG
    }
    return seg
  }).join('/')
}

const inferQueryScalarType = (val: string): string =>
  val === '' ? '' : NUMERIC_RE.test(val) ? '<num>' : (val === 'true' || val === 'false') ? '<bool>' : '<str>'

export function sanitizeQueryString(rawSearch: string): string {
  if (!rawSearch || rawSearch === '?') return rawSearch
  const parts: string[] = []
  for (const p of pairs(rawSearch)) {
    if (!p.raw) {
      parts.push('')
      continue
    }
    if (!p.hasEq) {
      if (isSensitiveValue(p.rawKey) || isSensitiveValue(p.key)) parts.push(REDACTED)
      else parts.push(isDataLikeKey(p.key) ? REDACTED : '<str>')
      continue
    }
    const outK = (isSensitiveValue(p.rawKey) || isSensitiveValue(p.key))
      ? REDACTED
      : isDataLikeKey(p.key) ? '<key>' : p.rawKey
    if (isSensitiveKey(p.key) || isSensitiveValue(p.val) || isSensitiveValue(p.rawVal)) {
      parts.push(`${outK}=${REDACTED}`)
    } else {
      parts.push(`${outK}=${inferQueryScalarType(p.val)}`)
    }
  }
  return '?' + parts.join('&')
}

export function sanitizeUrl(
  raw: string | URL,
  opts?: { maxLen?: number },
): { url: string; path: string; authority: string; scheme: 'http' | 'https' } {
  const maxLen = opts?.maxLen ?? 2048
  const u = typeof raw === 'string' ? URL.parse(raw) : raw
  if (!u) {
    const rawStr = String(raw)
    const qIdx = rawStr.indexOf('?')
    const rawPrefix = qIdx >= 0 ? rawStr.slice(0, qIdx) : rawStr
    const rawSearch = qIdx >= 0 ? rawStr.slice(qIdx) : ''
    const scrubbedPrefix = scrubText(rawPrefix).text
    const sq = rawSearch ? sanitizeQueryString(rawSearch) : ''
    return {
      url: truncateUtf8HeadTail(scrubbedPrefix + sq, maxLen),
      path: '/',
      authority: '',
      scheme: 'http',
    }
  }
  const scheme: 'http' | 'https' = u.protocol === 'https:' ? 'https' : 'http'
  const authority = scrubText(u.host).text
  const path = sanitizePath(u.pathname)
  const search = sanitizeQueryString(u.search)
  const full = `${scheme}://${authority}${path}${search}`
  return {
    url: truncateUtf8HeadTail(full, maxLen, Math.floor(maxLen * 0.75), Math.floor(maxLen * 0.25)),
    path: truncateUtf8HeadTail(path, 1024, 768, 252),
    authority: truncateUtf8HeadTail(authority, 256),
    scheme,
  }
}
