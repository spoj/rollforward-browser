import type http from 'node:http'
import { isTokenShaped, safeDecodeURIComponent } from './shared/redact.ts'

export {
  REDACT_V,
  REDACTED,
  REDACTED_SEG,
  SECRET_PATTERNS,
  SINGLE_SECRET_PATTERNS,
  buildBodyShape,
  buildFormBodyShape,
  isDataLikeKey,
  isSensitiveContainerKey,
  isSensitiveKey,
  isSensitiveValue,
  isTokenShaped,
  pairs,
  parseJsonSafe,
  safeDecodeURIComponent,
  sanitizePath,
  sanitizeQueryString,
  sanitizeUrl,
  scanJsonDuplicateKeys,
  scrubStructuralKey,
  scrubText,
  shannonEntropy,
  tokenizeKey,
  truncateUtf8HeadTail,
  type FormPair,
} from './shared/redact.ts'

const TRUSTED_HEADER_BUDGET = 16_384
const TRUSTED_DRIVE_BUDGET = 16_384
const LRU_MAX_ENTRIES = 512
const LRU_MAX_BYTES = 65_536
const MIN_TRUSTED_LEN = 6

const AUTH_HOST_RE = /^(?:login|signin|sso|auth|idp|sts|adfs|oauth|accounts)\.|(?:^|\.)(?:okta|oktapreview|auth0|onelogin|pingidentity|duosecurity|login\.microsoftonline|login\.live)\.com$/i
const AUTH_PATH_RE = /(?:^|\/)(?:login|log-in|signin|sign-in|sign_in|logout|auth|authenticate|authentication|oauth|oauth2|oidc|saml|saml2|sso|adfs|token|tokenrequest|authorize|callback|mfa|2fa|otp|totp|webauthn|passkey|password|passwd|reset-password|forgot-password|change-password|j_security_check|kmsi)(?:\/|$)/i

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

// Per-connection human /view/drive input buffer so concurrent drivers never interleave keystrokes.
export class DriveInputBuffer {
  private buf = ''
  private vault: SecretVault

  constructor(vault: SecretVault) {
    this.vault = vault
  }

  onEvent(method: string, params?: Record<string, unknown>): void {
    if (method === 'Input.insertText') {
      const text = params?.text
      if (typeof text === 'string' && text.length) {
        if (this.buf.length + text.length <= 4096) this.buf += text
      }
      return
    }
    if (method === 'Input.dispatchMouseEvent') {
      if (params?.type === 'mousePressed') this.flush()
      return
    }
    if (method === 'Input.dispatchKeyEvent') {
      const type = params?.type
      const key = typeof params?.key === 'string' ? params.key : ''
      const text = typeof params?.text === 'string' ? params.text : ''
      const modifiers = typeof params?.modifiers === 'number' ? params.modifiers : 0
      if (type === 'keyUp') return
      if (key === 'Backspace') {
        if (this.buf.length) this.buf = this.buf.slice(0, -1)
        return
      }
      if (key === 'Enter' || key === 'Tab' || text === '\r' || text === '\n' || text === '\t') {
        this.flush()
        return
      }
      if (key === 'ArrowLeft' || key === 'ArrowRight' || key === 'ArrowUp' || key === 'ArrowDown' || key === 'Home' || key === 'End' || key === 'Delete') {
        this.buf = ''
        return
      }
      if ((type === 'keyDown' || type === 'char') && text.length > 0 && (modifiers & 6) === 0) {
        if (this.buf.length + text.length <= 4096) this.buf += text
      }
    }
  }

  flush(): void {
    const val = this.buf
    this.buf = ''
    if (val.length >= MIN_TRUSTED_LEN) this.vault.addTrustedDrive(val)
  }

  clear(): void {
    this.buf = ''
  }
}

export class SecretVault {
  private trustedHeaders = new Set<string>()
  private trustedHeaderBytes = 0
  private trustedDrive = new Set<string>()
  private trustedDriveBytes = 0
  private lru = new Map<string, number>()
  private lruBytes = 0
  private dirty = false
  private regex: RegExp | null = null

  get empty(): boolean {
    return this.trustedHeaders.size === 0 && this.trustedDrive.size === 0 && this.lru.size === 0
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

  createDriveBuffer(): DriveInputBuffer {
    return new DriveInputBuffer(this)
  }

  private compile(): RegExp | null {
    if (!this.dirty) return this.regex
    this.dirty = false
    const variants = new Set<string>()
    const addVariants = (secret: string) => {
      variants.add(secret)
      const lower = secret.length >= 8 ? secret.toLowerCase() : secret
      if (lower !== secret) variants.add(lower)
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
    this.dirty = false
    this.regex = null
  }
}

export function scrubDeep<T>(value: T, vault?: SecretVault): T {
  if (!vault || vault.empty || value == null) return value
  const walk = (v: unknown, depth: number): unknown => {
    if (depth > 16 || v == null) return v
    if (typeof v === 'string') return vault.scrub(v).text
    if (Array.isArray(v)) return v.map(el => walk(el, depth + 1))
    if (typeof v === 'object') {
      const out: Record<string, unknown> = {}
      for (const [k, child] of Object.entries(v as Record<string, unknown>)) {
        const sk = vault.scrub(k)
        out[sk.count > 0 ? '[REDACTED:vault]' : k] = walk(child, depth + 1)
      }
      return out
    }
    return v
  }
  return walk(value, 0) as T
}

export function normalizePathForAuth(rawPath: string): string {
  // Split on '/' before percent-decoding so %2F inside a matrix parameter stays in-segment.
  const rawSegs = rawPath.split('/')
  const parts: string[] = []
  for (let i = 0; i < rawSegs.length; i++) {
    const raw = rawSegs[i]
    if (!raw) continue
    const preStrip = raw.split(';')[0]
    const swallowsNext = preStrip.toLowerCase() === 'formservice' && /;[^;=]+=$/.test(raw)
    if (swallowsNext) i++
    const decoded = safeDecodeURIComponent(preStrip)
    for (const sub of decoded.split('/')) {
      if (!sub || sub === '.') continue
      if (sub === '..') {
        parts.pop()
        continue
      }
      const base = sub.split(';')[0]
      if (base) parts.push(base)
    }
  }
  return '/' + parts.join('/')
}

export function isAuthUrl(raw: string | URL): boolean {
  const u = typeof raw === 'string' ? URL.parse(raw) : raw
  if (!u) return false
  const canonicalHost = u.hostname.replace(/\.+$/, '')
  if (AUTH_HOST_RE.test(canonicalHost)) return true
  const norm = normalizePathForAuth(u.pathname)
  return AUTH_PATH_RE.test(norm)
}
