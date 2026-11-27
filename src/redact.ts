import type http from 'node:http'

export const REDACT_V = 1

export type ProjectionMode = 'semantic' | 'semantic+samples'

const TRUSTED_HEADER_BUDGET = 16_384
const TRUSTED_DRIVE_BUDGET = 16_384
const LRU_MAX_ENTRIES = 512
const LRU_MAX_BYTES = 65_536
const MIN_TRUSTED_LEN = 6

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

const AUTH_HOST_RE = /^(?:login|signin|sso|auth|idp|sts|adfs|oauth|accounts)\.|(?:^|\.)(?:okta|oktapreview|auth0|onelogin|pingidentity|duosecurity|login\.microsoftonline|login\.live)\.com$/i
const AUTH_PATH_RE = /(?:^|\/)(?:login|log-in|signin|sign-in|sign_in|logout|auth|authenticate|authentication|oauth|oauth2|oidc|saml|saml2|sso|adfs|token|tokenrequest|authorize|mfa|2fa|otp|totp|webauthn|passkey|password|passwd|reset-password|forgot-password|change-password|j_security_check|kmsi)(?:\/|$)/i

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}(?:[T\s]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/i
const NUMERIC_RE = /^[+-]?\d+(?:\.\d+)?$/
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const BASE64_HEX_RE = /^[A-Za-z0-9+/=_-]+$/

const SECRET_PATTERNS: RegExp[] = [
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  /\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=._-]{8,}/gi,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
  /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  /\bAIza[0-9A-Za-z_-]{30,}\b/g,
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g,
  /([?&]sig=)[A-Za-z0-9%+/=]{20,}/gi,
]

const SINGLE_SECRET_PATTERNS: RegExp[] = [
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
  /^(?:Bearer|Basic)\s+\S{8,}$/i,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/,
  /\bsk-[A-Za-z0-9_-]{20,}\b/,
  /\bAIza[0-9A-Za-z_-]{30,}\b/,
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/,
  /(?:^|[?&])sig=[A-Za-z0-9%+/=]{20,}/i,
]

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
  if (typeof value !== 'string') return false
  if (value.length < 16) return false
  if (NUMERIC_RE.test(value)) return false
  return shannonEntropy(value) >= 3.5
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

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

export class SecretVault {
  private trustedHeaders = new Set<string>()
  private trustedHeaderBytes = 0
  private trustedDrive = new Set<string>()
  private trustedDriveBytes = 0
  private lru = new Map<string, number>()
  private lruBytes = 0
  private driveBuf = ''
  private dirty = false
  private regex: RegExp | null = null

  get empty(): boolean {
    return this.trustedHeaders.size === 0 && this.trustedDrive.size === 0 && this.lru.size === 0
  }

  get trustedSize(): number {
    return this.trustedHeaders.size + this.trustedDrive.size
  }

  get lruSize(): number {
    return this.lru.size
  }

  addTrustedHeader(value: string): boolean {
    if (typeof value !== 'string' || value.length < MIN_TRUSTED_LEN) return false
    if (this.trustedHeaders.has(value)) return true
    const bytes = Buffer.byteLength(value)
    if (this.trustedHeaderBytes + bytes > TRUSTED_HEADER_BUDGET) return false
    this.trustedHeaders.add(value)
    this.trustedHeaderBytes += bytes
    if (this.lru.has(value)) {
      this.lruBytes -= this.lru.get(value)!
      this.lru.delete(value)
    }
    this.dirty = true
    return true
  }

  addTrustedDrive(value: string): boolean {
    if (typeof value !== 'string' || value.length < MIN_TRUSTED_LEN) return false
    if (this.trustedDrive.has(value)) return true
    const bytes = Buffer.byteLength(value)
    if (this.trustedDriveBytes + bytes > TRUSTED_DRIVE_BUDGET) return false
    this.trustedDrive.add(value)
    this.trustedDriveBytes += bytes
    if (this.lru.has(value)) {
      this.lruBytes -= this.lru.get(value)!
      this.lru.delete(value)
    }
    this.dirty = true
    return true
  }

  addToken(value: string): boolean {
    if (!isTokenShaped(value)) return false
    if (this.trustedHeaders.has(value) || this.trustedDrive.has(value)) return true
    const bytes = Buffer.byteLength(value)
    if (bytes > LRU_MAX_BYTES) return false
    if (this.lru.has(value)) {
      this.lru.delete(value)
      this.lru.set(value, bytes)
      return true
    }
    while (this.lru.size >= LRU_MAX_ENTRIES || this.lruBytes + bytes > LRU_MAX_BYTES) {
      const oldest = this.lru.keys().next().value
      if (oldest === undefined) break
      this.lruBytes -= this.lru.get(oldest)!
      this.lru.delete(oldest)
    }
    this.lru.set(value, bytes)
    this.lruBytes += bytes
    this.dirty = true
    return true
  }

  ingestStorageState(state: unknown): void {
    if (!state || typeof state !== 'object') return
    const st = state as { cookies?: Array<{ value?: unknown }>; origins?: Array<{ localStorage?: Array<{ value?: unknown }> }> }
    if (Array.isArray(st.cookies)) {
      for (const c of st.cookies) {
        if (typeof c?.value === 'string') {
          this.addToken(c.value)
          const dec = safeDecodeURIComponent(c.value)
          if (dec !== c.value) this.addToken(dec)
        }
      }
    }
    if (Array.isArray(st.origins)) {
      for (const o of st.origins) {
        if (!Array.isArray(o?.localStorage)) continue
        for (const item of o.localStorage) {
          if (typeof item?.value !== 'string') continue
          this.addToken(item.value)
          const trimmed = item.value.trim()
          if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
            try {
              const parsed = JSON.parse(trimmed)
              let seen = 0
              const walk = (v: unknown, depth: number) => {
                if (depth > 4 || seen >= 64) return
                if (typeof v === 'string') {
                  seen++
                  this.addToken(v)
                } else if (Array.isArray(v)) {
                  for (const el of v) walk(el, depth + 1)
                } else if (v && typeof v === 'object') {
                  for (const val of Object.values(v)) walk(val, depth + 1)
                }
              }
              walk(parsed, 0)
            } catch {}
          }
        }
      }
    }
  }

  ingestRequestHeaders(headers: http.IncomingHttpHeaders): void {
    const cookie = headers.cookie
    if (typeof cookie === 'string') {
      for (const part of cookie.split(';')) {
        const eq = part.indexOf('=')
        if (eq < 0) continue
        const raw = part.slice(eq + 1).trim()
        if (raw) {
          this.addToken(raw)
          const dec = safeDecodeURIComponent(raw)
          if (dec !== raw) this.addToken(dec)
        }
      }
    }
    const auth = headers.authorization
    if (typeof auth === 'string') {
      const stripped = auth.replace(/^(?:Bearer|Basic|Token)\s+/i, '').trim()
      if (stripped) this.addToken(stripped)
      this.addToken(auth.trim())
    }
    for (const h of ['x-csrf-token', 'x-xsrf-token', 'x-requestdigest'] as const) {
      const v = headers[h]
      if (typeof v === 'string' && v.trim()) this.addToken(v.trim())
    }
  }

  ingestSetCookie(setCookie: string | string[] | undefined): void {
    if (!setCookie) return
    const list = Array.isArray(setCookie) ? setCookie : [setCookie]
    for (const header of list) {
      if (typeof header !== 'string') continue
      const first = header.split(';')[0]
      const eq = first.indexOf('=')
      if (eq < 0) continue
      const val = first.slice(eq + 1).trim()
      if (!val) continue
      this.addToken(val)
      const dec = safeDecodeURIComponent(val)
      if (dec !== val) this.addToken(dec)
    }
  }

  onDriveEvent(method: string, params?: Record<string, unknown>): void {
    if (method === 'Input.insertText') {
      const text = params?.text
      if (typeof text === 'string' && text.length) {
        if (this.driveBuf.length + text.length <= 4096) this.driveBuf += text
      }
      return
    }
    if (method === 'Input.dispatchMouseEvent') {
      if (params?.type === 'mousePressed') this.flushDriveBuffer()
      return
    }
    if (method === 'Input.dispatchKeyEvent') {
      const type = params?.type
      const key = typeof params?.key === 'string' ? params.key : ''
      const text = typeof params?.text === 'string' ? params.text : ''
      const modifiers = typeof params?.modifiers === 'number' ? params.modifiers : 0
      if (type === 'keyUp') return
      if (key === 'Backspace') {
        if (this.driveBuf.length) this.driveBuf = this.driveBuf.slice(0, -1)
        return
      }
      if (key === 'Enter' || key === 'Tab' || text === '\r' || text === '\n' || text === '\t') {
        this.flushDriveBuffer()
        return
      }
      if (key === 'ArrowLeft' || key === 'ArrowRight' || key === 'ArrowUp' || key === 'ArrowDown' || key === 'Home' || key === 'End' || key === 'Delete') {
        this.driveBuf = ''
        return
      }
      if ((type === 'keyDown' || type === 'char') && text.length > 0 && (modifiers & 6) === 0) {
        if (this.driveBuf.length + text.length <= 4096) this.driveBuf += text
      }
    }
  }

  flushDriveBuffer(): void {
    const val = this.driveBuf
    this.driveBuf = ''
    if (val.length >= MIN_TRUSTED_LEN) this.addTrustedDrive(val)
  }

  private compile(): RegExp | null {
    if (!this.dirty) return this.regex
    this.dirty = false
    const variants = new Set<string>()
    const addVariants = (secret: string) => {
      variants.add(secret)
      try {
        const enc = encodeURIComponent(secret)
        if (enc !== secret) variants.add(enc)
        const strictEnc = enc.replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase())
        if (strictEnc !== enc) variants.add(strictEnc)
        const formEnc = strictEnc.replace(/%20/g, '+')
        if (formEnc !== strictEnc) variants.add(formEnc)
      } catch {}
      const jsonEsc = JSON.stringify(secret).slice(1, -1)
      if (jsonEsc !== secret) variants.add(jsonEsc)
    }
    for (const s of this.trustedHeaders) addVariants(s)
    for (const s of this.trustedDrive) addVariants(s)
    for (const s of this.lru.keys()) addVariants(s)
    if (!variants.size) {
      this.regex = null
      return null
    }
    const sorted = [...variants].sort((a, b) => b.length - a.length)
    this.regex = new RegExp(sorted.map(escapeRe).join('|'), 'g')
    return this.regex
  }

  scrub(input: string): { text: string; count: number } {
    if (!input || this.empty) return { text: input, count: 0 }
    const re = this.compile()
    if (!re) return { text: input, count: 0 }
    re.lastIndex = 0
    let count = 0
    const text = input.replace(re, () => {
      count++
      return '[REDACTED:vault]'
    })
    return { text, count }
  }

  clear(): void {
    this.trustedHeaders.clear()
    this.trustedHeaderBytes = 0
    this.trustedDrive.clear()
    this.trustedDriveBytes = 0
    this.lru.clear()
    this.lruBytes = 0
    this.driveBuf = ''
    this.dirty = false
    this.regex = null
  }
}

export function normalizePathForAuth(rawPath: string): string {
  const decoded = safeDecodeURIComponent(rawPath)
  // Strip WebLogic/servlet matrix params from the first ';' onward so `/formservice;x=/login` resolves to `/formservice`
  // while `/login;jsessionid=123` resolves to `/login`.
  const semiIdx = decoded.indexOf(';')
  const stripped = semiIdx >= 0 ? decoded.slice(0, semiIdx) : decoded
  const parts: string[] = []
  for (const seg of stripped.split('/')) {
    if (!seg || seg === '.') continue
    if (seg === '..') {
      parts.pop()
      continue
    }
    const cleanSeg = seg.split(';')[0]
    if (cleanSeg) parts.push(cleanSeg)
  }
  return '/' + parts.join('/')
}

export function isAuthUrl(raw: string | URL): boolean {
  const u = typeof raw === 'string' ? URL.parse(raw) : raw
  if (!u) return false
  if (AUTH_HOST_RE.test(u.hostname)) return true
  const norm = normalizePathForAuth(u.pathname)
  return AUTH_PATH_RE.test(norm)
}

export function tokenizeKey(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean)
}

export function isSensitiveContainerKey(key: string): boolean {
  const lower = key.toLowerCase()
  if (SENSITIVE_CONTAINERS.has(lower)) return true
  const tokens = tokenizeKey(key)
  return tokens.length === 1 && SENSITIVE_CONTAINERS.has(tokens[0])
}

export function isSensitiveKey(key: string): boolean {
  const tokens = tokenizeKey(key)
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
  if (tokens.some(t => UNAMBIGUOUS_TOKENS.has(t))) return true
  return false
}

export function isSensitiveValue(s: string): boolean {
  if (!s) return false
  for (const re of SINGLE_SECRET_PATTERNS) {
    if (re.test(s)) return true
  }
  if (
    s.length >= 32 &&
    BASE64_HEX_RE.test(s) &&
    !UUID_RE.test(s) &&
    !ISO_DATE_RE.test(s) &&
    !NUMERIC_RE.test(s) &&
    shannonEntropy(s) >= 4.0
  ) {
    return true
  }
  return false
}

export function scrubText(input: string, vault?: SecretVault): { text: string; vaultRedactions: number } {
  if (!input) return { text: input, vaultRedactions: 0 }
  let text = input
  let vaultRedactions = 0
  if (vault) {
    const v = vault.scrub(text)
    text = v.text
    vaultRedactions += v.count
  }
  for (const re of SECRET_PATTERNS) {
    re.lastIndex = 0
    text = text.replace(re, (m, g1) => (typeof g1 === 'string' && m.startsWith(g1) ? `${g1}[REDACTED]` : '[REDACTED]'))
  }
  return { text, vaultRedactions }
}

// Single-pass JSON scanner for duplicate keys within any object, honoring JSON string escapes.
export function scanJsonDuplicateKeys(text: string): boolean {
  const len = text.length
  let i = 0
  type Frame = { type: '{'; keys: Set<string>; expectKey: boolean; expectColon: boolean } | { type: '[' }
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
      stack.push({ type: '{', keys: new Set(), expectKey: true, expectColon: false })
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
      if (top && top.type === '{') {
        top.expectColon = false
        top.expectKey = false
      }
      i++
    } else if (ch === ',') {
      if (top && top.type === '{') {
        top.expectKey = true
        top.expectColon = false
      }
      i++
    } else if (ch === '"') {
      const str = readString()
      if (str === null) return false
      if (top && top.type === '{' && top.expectKey) {
        if (top.keys.has(str)) return true
        top.keys.add(str)
        top.expectKey = false
        top.expectColon = true
      }
    } else {
      // primitive token
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

const rawJsonSupported = typeof (JSON as any).rawJSON === 'function' && typeof (JSON as any).isRawJSON === 'function'

export function parseJsonSafe(text: string): { ok: true; value: unknown; dupKeys: boolean } | { ok: false } {
  const trimmed = text.trim()
  if (!trimmed) return { ok: false }
  const first = trimmed[0]
  if (first !== '{' && first !== '[' && first !== '"' && first !== '-' && !(first >= '0' && first <= '9') && first !== 't' && first !== 'f' && first !== 'n') {
    return { ok: false }
  }
  try {
    const value = rawJsonSupported
      ? JSON.parse(trimmed, (_k, v, ctx?: { source?: string }) =>
          typeof v === 'number' && ctx?.source ? (JSON as any).rawJSON(ctx.source) : v,
        )
      : JSON.parse(trimmed)
    const dupKeys = scanJsonDuplicateKeys(trimmed)
    return { ok: true, value, dupKeys }
  } catch {
    return { ok: false }
  }
}

export function isRawJsonLeaf(v: unknown): boolean {
  return rawJsonSupported && (JSON as any).isRawJSON(v)
}

export function redactJsonValue(
  value: unknown,
  vault?: SecretVault,
  inheritSensitive = false,
): { value: unknown; vaultRedactions: number } {
  let vaultRedactions = 0

  const walk = (v: unknown, sensitive: boolean, depth: number): unknown => {
    if (depth > 32) return '[REDACTED:depth]'
    if (v === null || v === undefined) return v
    if (isRawJsonLeaf(v)) {
      if (sensitive) return '[REDACTED]'
      const raw = (v as { rawJSON: string }).rawJSON
      if (vault) {
        const s = vault.scrub(raw)
        if (s.count > 0) {
          vaultRedactions += s.count
          return '[REDACTED:vault]'
        }
      }
      return v
    }
    if (typeof v === 'string') {
      if (sensitive) return '[REDACTED]'
      let out = v
      if (vault) {
        const s = vault.scrub(out)
        if (s.count > 0) {
          vaultRedactions += s.count
          out = s.text
        }
      }
      if (isSensitiveValue(out)) return '[REDACTED]'
      return out
    }
    if (typeof v === 'number' || typeof v === 'boolean') {
      if (sensitive) return '[REDACTED]'
      if (typeof v === 'number' && vault) {
        const s = vault.scrub(String(v))
        if (s.count > 0) {
          vaultRedactions += s.count
          return '[REDACTED:vault]'
        }
      }
      return v
    }
    if (Array.isArray(v)) {
      return v.map(el => walk(el, sensitive, depth + 1))
    }
    if (typeof v === 'object') {
      const out: Record<string, unknown> = {}
      for (const [k, child] of Object.entries(v as Record<string, unknown>)) {
        const childSensitive = sensitive || isSensitiveContainerKey(k) || isSensitiveKey(k)
        out[k] = walk(child, childSensitive, depth + 1)
      }
      return out
    }
    return v
  }

  return { value: walk(value, inheritSensitive, 0), vaultRedactions }
}

export function isDataLikeKey(key: string): boolean {
  if (!key) return false
  if (key.length > 32) return true
  if (EMAIL_RE.test(key)) return true
  if (UUID_RE.test(key)) return true
  if (NUMERIC_RE.test(key)) return true
  if (isSensitiveValue(key)) return true
  if (key.length >= 20 && BASE64_HEX_RE.test(key) && shannonEntropy(key) >= 4.0) return true
  return false
}

export function buildBodyShape(
  value: unknown,
  vault?: SecretVault,
  maxDepth = 6,
  maxPaths = 64,
): { shape: Record<string, string>; vaultRedactions: number } {
  const shape: Record<string, string> = {}
  let count = 0
  let vaultRedactions = 0

  const add = (path: string, type: string) => {
    if (path in shape) {
      if (shape[path] !== type) shape[path] = 'mixed'
      return
    }
    if (count >= maxPaths) return
    shape[path] = type
    count++
  }

  const scrubKey = (k: string): string => {
    if (vault) {
      const s = vault.scrub(k)
      if (s.count > 0) {
        vaultRedactions += s.count
        return '<key>'
      }
    }
    if (isDataLikeKey(k)) return '<key>'
    return k
  }

  const scalarType = (v: unknown): string => {
    if (v === null) return 'null'
    if (isRawJsonLeaf(v) || typeof v === 'number') return 'number'
    if (typeof v === 'boolean') return 'boolean'
    if (typeof v === 'string') return 'string'
    return typeof v
  }

  const walk = (v: unknown, prefix: string, depth: number) => {
    if (count >= maxPaths) return
    if (v === null || isRawJsonLeaf(v) || typeof v !== 'object') {
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
        if (el !== null && typeof el === 'object' && !isRawJsonLeaf(el)) {
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
    if (entries.length === 0) {
      add(prefix || '$', 'object')
      return
    }
    if (depth >= maxDepth) {
      add(prefix || '$', 'object')
      return
    }
    for (const [rawKey, child] of entries) {
      if (count >= maxPaths) break
      const k = scrubKey(rawKey)
      const nextPath = prefix ? `${prefix}.${k}` : k
      walk(child, nextPath, depth + 1)
    }
  }

  walk(value, '', 0)
  return { shape, vaultRedactions }
}

const inferQueryScalarType = (val: string): string => {
  if (val === '') return ''
  if (NUMERIC_RE.test(val)) return '<num>'
  if (val === 'true' || val === 'false') return '<bool>'
  return '<str>'
}

export function buildFormBodyShape(raw: string, vault?: SecretVault, maxPaths = 64): { shape: Record<string, string>; vaultRedactions: number } {
  const shape: Record<string, string> = {}
  let count = 0
  let vaultRedactions = 0
  for (const pair of raw.split('&')) {
    if (!pair || count >= maxPaths) continue
    const eq = pair.indexOf('=')
    const rawK = eq >= 0 ? pair.slice(0, eq) : pair
    const rawV = eq >= 0 ? pair.slice(eq + 1) : ''
    let k = safeDecodeURIComponent(rawK.replace(/\+/g, ' '))
    const v = safeDecodeURIComponent(rawV.replace(/\+/g, ' '))
    if (vault) {
      const s = vault.scrub(k)
      if (s.count > 0) {
        vaultRedactions += s.count
        k = '<key>'
      }
    }
    if (k !== '<key>' && isDataLikeKey(k)) k = '<key>'
    const t = v === '' ? 'empty' : NUMERIC_RE.test(v) ? 'number' : (v === 'true' || v === 'false') ? 'boolean' : 'string'
    if (!(k in shape)) {
      shape[k] = t
      count++
    } else if (shape[k] !== t) {
      shape[k] = 'mixed'
    }
  }
  return { shape, vaultRedactions }
}

export function redactFormBody(raw: string, vault?: SecretVault): { text: string; vaultRedactions: number } {
  let vaultRedactions = 0
  const parts = raw.split('&').map(pair => {
    if (!pair) return pair
    const eq = pair.indexOf('=')
    if (eq < 0) {
      if (!vault) return pair
      const s = vault.scrub(pair)
      vaultRedactions += s.count
      return s.text
    }
    const rawK = pair.slice(0, eq)
    const rawV = pair.slice(eq + 1)
    const decK = safeDecodeURIComponent(rawK.replace(/\+/g, ' '))
    const decV = safeDecodeURIComponent(rawV.replace(/\+/g, ' '))
    if (vault) {
      const sv1 = vault.scrub(rawV)
      const sv2 = vault.scrub(decV)
      if (sv1.count > 0 || sv2.count > 0) {
        vaultRedactions += Math.max(sv1.count, sv2.count)
        return `${rawK}=[REDACTED:vault]`
      }
    }
    if (isSensitiveKey(decK) || isSensitiveValue(decV)) {
      return `${rawK}=[REDACTED]`
    }
    return pair
  })
  return { text: parts.join('&'), vaultRedactions }
}

export function redactPlainText(raw: string, vault?: SecretVault): { text: string; vaultRedactions: number } {
  return scrubText(raw, vault)
}

const isHighSurrogate = (code: number) => code >= 0xd800 && code <= 0xdbff
const isLowSurrogate = (code: number) => code >= 0xdc00 && code <= 0xdfff

export function truncateHeadTail(str: string, maxLen = 2048, headLen = 1536, tailLen = 512): string {
  if (str.length <= maxLen) return str
  let h = Math.min(headLen, maxLen - 1)
  let t = Math.min(tailLen, maxLen - h - 1)
  if (t < 0) t = 0
  let headEnd = h
  while (headEnd > 0 && isHighSurrogate(str.charCodeAt(headEnd - 1))) headEnd--
  if (headEnd >= 1 && str[headEnd - 1] === '%') headEnd -= 1
  else if (headEnd >= 2 && str[headEnd - 2] === '%' && /[0-9a-fA-F]/.test(str[headEnd - 1])) headEnd -= 2

  let tailStart = str.length - t
  while (tailStart < str.length && isLowSurrogate(str.charCodeAt(tailStart))) tailStart++
  if (tailStart >= 1 && str[tailStart - 1] === '%') tailStart = Math.min(str.length, tailStart + 2)
  else if (tailStart >= 2 && str[tailStart - 2] === '%' && /[0-9a-fA-F]/.test(str[tailStart - 1])) tailStart = Math.min(str.length, tailStart + 1)

  if (tailStart <= headEnd) return str.slice(0, maxLen)
  return `${str.slice(0, headEnd)}…${str.slice(tailStart)}`
}

export function sanitizePath(pathname: string, vault?: SecretVault): { path: string; vaultRedactions: number } {
  let vaultRedactions = 0
  const segments = pathname.split('/').map(seg => {
    if (!seg) return seg
    let out = seg
    if (vault) {
      const sv = vault.scrub(out)
      if (sv.count > 0) {
        vaultRedactions += sv.count
        out = sv.text
      }
      const dec = safeDecodeURIComponent(out)
      if (dec !== out) {
        const svDec = vault.scrub(dec)
        if (svDec.count > 0) {
          vaultRedactions += svDec.count
          return '[REDACTED:vault]'
        }
      }
    }
    if (out.includes('[REDACTED')) return out
    const decSeg = safeDecodeURIComponent(out)
    if (isSensitiveValue(decSeg)) return '[REDACTED:seg]'
    if (
      decSeg.length >= 24 &&
      !UUID_RE.test(decSeg) &&
      !ISO_DATE_RE.test(decSeg) &&
      BASE64_HEX_RE.test(decSeg) &&
      shannonEntropy(decSeg) >= 4.0
    ) {
      return '[REDACTED:seg]'
    }
    return out
  })
  return { path: segments.join('/'), vaultRedactions }
}

function sanitizeQueryString(
  rawSearch: string,
  projection: ProjectionMode,
  vault?: SecretVault,
): { search: string; vaultRedactions: number } {
  if (!rawSearch || rawSearch === '?') return { search: rawSearch, vaultRedactions: 0 }
  const q = rawSearch.startsWith('?') ? rawSearch.slice(1) : rawSearch
  let vaultRedactions = 0
  const parts = q.split('&').map(part => {
    if (!part) return part
    const eq = part.indexOf('=')
    if (eq < 0) {
      if (!vault) return part
      const s = vault.scrub(part)
      vaultRedactions += s.count
      return s.text
    }
    const rawK = part.slice(0, eq)
    const rawV = part.slice(eq + 1)
    let outK = rawK
    if (vault) {
      const sk = vault.scrub(rawK)
      if (sk.count > 0) {
        vaultRedactions += sk.count
        outK = sk.text
      }
    }
    const decK = safeDecodeURIComponent(rawK.replace(/\+/g, ' '))
    const decV = safeDecodeURIComponent(rawV.replace(/\+/g, ' '))
    if (vault) {
      const sv1 = vault.scrub(rawV)
      const sv2 = decV !== rawV ? vault.scrub(decV) : { text: decV, count: 0 }
      if (sv1.count > 0 || sv2.count > 0) {
        vaultRedactions += Math.max(sv1.count, sv2.count)
        return `${outK}=[REDACTED:vault]`
      }
    }
    if (isSensitiveKey(decK) || isSensitiveValue(decV) || isSensitiveValue(rawV)) {
      return `${outK}=[REDACTED]`
    }
    if (projection === 'semantic') {
      const templated = inferQueryScalarType(decV)
      return `${outK}=${templated}`
    }
    // semantic+samples: preserve raw span untouched (keeps %20, etc.)
    return `${outK}=${rawV}`
  })
  return { search: '?' + parts.join('&'), vaultRedactions }
}

export function sanitizeUrl(
  raw: string | URL,
  opts: { projection: ProjectionMode; vault?: SecretVault; maxLen?: number },
): { url: string; path: string; authority: string; scheme: 'http' | 'https'; vaultRedactions: number } {
  const maxLen = opts.maxLen ?? 2048
  const u = typeof raw === 'string' ? URL.parse(raw) : raw
  if (!u) {
    const scrubbed = scrubText(String(raw), opts.vault)
    return {
      url: truncateHeadTail(scrubbed.text, maxLen),
      path: '/',
      authority: '',
      scheme: 'http',
      vaultRedactions: scrubbed.vaultRedactions,
    }
  }
  const scheme: 'http' | 'https' = u.protocol === 'https:' ? 'https' : 'http'
  const authority = u.host
  const origin = `${scheme}://${authority}`
  const sp = sanitizePath(u.pathname, opts.vault)
  const sq = sanitizeQueryString(u.search, opts.projection, opts.vault)
  let vaultRedactions = sp.vaultRedactions + sq.vaultRedactions
  let full = `${origin}${sp.path}${sq.search}`
  if (opts.vault) {
    const finalScrub = opts.vault.scrub(full)
    if (finalScrub.count > 0) {
      vaultRedactions += finalScrub.count
      full = finalScrub.text
    }
  }
  return {
    url: truncateHeadTail(full, maxLen),
    path: truncateHeadTail(sp.path, 1024, 768, 256),
    authority,
    scheme,
    vaultRedactions,
  }
}
