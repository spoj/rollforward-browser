import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  SecretVault,
  buildBodyShape,
  isAuthUrl,
  isSensitiveKey,
  isTokenShaped,
  parseJsonSafe,
  redactJsonValue,
  sanitizeUrl,
  truncateHeadTail,
} from '../src/redact.ts'

test('tokenized key matching preserves ordinary business fields and redacts credentials + compound suffixes', () => {
  const preserve = [
    'AuthorizationNumber',
    'PrimaryKey',
    'TrainingSession',
    'PassFail',
    'PostalCode',
    'Secretary',
    'CreditLimit',
    'Japan',
    'AccountNumber',
    'OrderCode',
    'InvoiceKey',
  ]
  for (const k of preserve) {
    assert.equal(isSensitiveKey(k), false, `expected ${k} to be preserved`)
  }

  const redact = [
    'Authorization',
    'authorization',
    'key',
    'code',
    'pin',
    'pass',
    'session',
    'auth',
    'sig',
    'apiKey',
    'FormDigestValue',
    'X-RequestDigest',
    'passcode',
    'verificationCode',
    'smsCode',
    'authCode',
    'passCode',
    'userPass',
    'userPin',
    'sessionKey',
    'authKey',
    'signingKey',
    'token',
    'client_secret',
    'access_token',
    'id_token',
    'refresh_token',
    'session_id',
    'sessionId',
    'auth_token',
    'jas_token',
    'code_verifier',
    'password',
    'xsrf',
    'csrf',
    'cvv',
    'ssn',
    'jasserver',
  ]
  for (const k of redact) {
    assert.equal(isSensitiveKey(k), true, `expected ${k} to be redacted`)
  }
})

test('JSON.rawJSON leaves are preserved under ordinary keys, redacted under secret keys and sensitive containers, and duplicate keys are detected', () => {
  const rawText = '{"amount":1.10,"bigId":12345678901234567890,"AuthorizationNumber":"AUTH-99","apiKey":998877,"credentials":{"user":"alice","pin":123456,"nested":{"x":true}},"a":1,"\\u0061":2}'
  const parsed = parseJsonSafe(rawText)
  assert.equal(parsed.ok, true)
  if (!parsed.ok) return
  assert.equal(parsed.dupKeys, true, 'detects unicode-escaped duplicate key')

  const { value } = redactJsonValue(parsed.value)
  const serialized = JSON.stringify(value)
  assert.match(serialized, /"amount":1\.10/)
  assert.match(serialized, /"bigId":12345678901234567890/)
  assert.match(serialized, /"AuthorizationNumber":"AUTH-99"/)
  assert.match(serialized, /"apiKey":"\[REDACTED\]"/)
  assert.match(serialized, /"credentials":\{"user":"\[REDACTED\]","pin":"\[REDACTED\]","nested":\{"x":"\[REDACTED\]"\}\}/)
})

test('bodyShape collapses arrays, strips scalar values, and scrubs data-like map keys to <key>', () => {
  const vault = new SecretVault()
  vault.addTrustedDrive('MySecretKeyName')
  const doc = {
    formName: 'P0411_W0411A',
    items: [
      { amount: 100.5, active: true },
      { amount: 200.0, active: false },
    ],
    byEmail: { 'jane.doe@example.com': { total: 5 } },
    byUuid: { '550e8400-e29b-41d4-a716-446655440000': 'ok' },
    byNum: { '123456': 'row' },
    byLong: { ['a'.repeat(33)]: 'val' },
    byVault: { MySecretKeyName: 'val' },
  }
  const { shape, vaultRedactions } = buildBodyShape(doc, vault)
  assert.equal(shape['formName'], 'string')
  assert.equal(shape['items[].amount'], 'number')
  assert.equal(shape['items[].active'], 'boolean')
  assert.equal(shape['byEmail.<key>.total'], 'number')
  assert.equal(shape['byUuid.<key>'], 'string')
  assert.equal(shape['byNum.<key>'], 'string')
  assert.equal(shape['byLong.<key>'], 'string')
  assert.equal(shape['byVault.<key>'], 'string')
  assert.equal(vaultRedactions, 1)
  const serialized = JSON.stringify(shape)
  assert.ok(!serialized.includes('jane.doe@example.com'))
  assert.ok(!serialized.includes('550e8400'))
  assert.ok(!serialized.includes('123456'))
  assert.ok(!serialized.includes('MySecretKeyName'))
  assert.ok(!serialized.includes('P0411_W0411A'))
})

test('SecretVault two-pool isolation prevents cookie poisoning, protects trusted drive inputs from 2,000 cookies & >64KiB storageState, and scrubs 6-digit OTP with Backspace', () => {
  const vault = new SecretVault()
  // Trusted header + human drive OTP with Backspace edit ("482917" typed as 482919 + Backspace + 7 + Enter)
  assert.equal(vault.addTrustedHeader('HeaderSecret-9988'), true)
  for (const ch of '482919') vault.onDriveEvent('Input.dispatchKeyEvent', { type: 'keyDown', key: ch, text: ch })
  vault.onDriveEvent('Input.dispatchKeyEvent', { type: 'rawKeyDown', key: 'Backspace' })
  vault.onDriveEvent('Input.dispatchKeyEvent', { type: 'keyDown', key: '7', text: '7' })
  vault.onDriveEvent('Input.dispatchKeyEvent', { type: 'rawKeyDown', key: 'Enter' })

  // Arrow key resets in-progress drive buffer
  vault.onDriveEvent('Input.insertText', { text: 'aborted' })
  vault.onDriveEvent('Input.dispatchKeyEvent', { type: 'rawKeyDown', key: 'ArrowLeft' })
  vault.onDriveEvent('Input.dispatchKeyEvent', { type: 'rawKeyDown', key: 'Enter' })
  assert.equal(vault.scrub('aborted').count, 0, 'arrow key reset drive buffer')

  // Human drive password flushed by mouse click
  vault.onDriveEvent('Input.insertText', { text: 'HumanPass!2026' })
  vault.onDriveEvent('Input.dispatchMouseEvent', { type: 'mousePressed' })

  // Attempt poisoning with numeric cookie (document.cookie = "z=98765432") both live and via storageState
  assert.equal(isTokenShaped('98765432'), false)
  assert.equal(isTokenShaped('98765432109876543210'), false, 'pure digits rejected')
  assert.equal(isTokenShaped('1234567890123456.78'), false, 'decimal amount rejected')
  vault.ingestRequestHeaders({ cookie: 'z=98765432' })
  vault.ingestSetCookie('z=98765432; Path=/')
  vault.ingestStorageState({ cookies: [{ name: 'z', value: '98765432' }], origins: [] })
  assert.equal(vault.scrub('AccountNumber=98765432').text, 'AccountNumber=98765432', 'numeric cookie never poisons AccountNumber')

  // Flood LRU pool with 2,000 random high-entropy cookies + >64 KiB M365 storageState
  const bigOrigins = [{
    origin: 'https://contoso.sharepoint.com',
    localStorage: Array.from({ length: 120 }, (_, i) => ({
      name: `msal.${i}`,
      value: `Tok${i.toString(36).padStart(4, '0')}_${Buffer.from(`seed-${i}-aB9!xZ#${i * 17}`).toString('base64url').repeat(20)}`,
    })),
  }]
  vault.ingestStorageState({ cookies: [], origins: bigOrigins })
  for (let i = 0; i < 2000; i++) {
    const tok = `c${i}_` + Buffer.from(`random-cookie-payload-${i}-!@#$%^&*()`).toString('base64url')
    vault.ingestSetCookie(`c${i}=${tok}; Path=/`)
  }
  assert.ok(vault.lruSize <= 512, 'LRU bounded to 512 entries')

  // Trusted pool MUST survive eviction completely intact!
  assert.equal(vault.scrub('otp=482917').text, 'otp=[REDACTED:vault]')
  assert.equal(vault.scrub('pw=HumanPass%212026').text, 'pw=[REDACTED:vault]', 'scrubs encodeURIComponent variant')
  assert.equal(vault.scrub('hdr=HeaderSecret-9988').text, 'hdr=[REDACTED:vault]')
})

test('normalized auth-URL denylist handles WebLogic matrix params, dot segments, trailing host dot, callbacks, and percent-encoding', () => {
  assert.equal(isAuthUrl('https://erp.example/jderest/v2/formservice;x=/login'), false, 'WebLogic ;x=/login matches §6.2 acceptance matrix (NOT auth URL)')
  assert.equal(isAuthUrl('https://erp.example/jderest/v2/formservice;x=%2Flogin'), false, 'in-segment matrix param stripped before decoding %2F')
  assert.equal(isAuthUrl('https://erp.example/jderest/v2/formservice;x=login'), false, 'in-segment matrix param stripped')
  assert.equal(isAuthUrl('https://erp.example/app;v=1/login'), true, 'real auth endpoint after matrix-parameterized segment IS auth URL')
  assert.equal(isAuthUrl('https://erp.example/sso/callback'), true, 'callback endpoint IS auth URL')
  assert.equal(isAuthUrl('https://login.microsoftonline.com./common/foo'), true, 'trailing DNS dot stripped before auth host check')
  assert.equal(isAuthUrl('https://erp.example/login;jsessionid=ABC123'), true)
  assert.equal(isAuthUrl('https://erp.example/foo/../login'), true)
  assert.equal(isAuthUrl('https://erp.example/%6c%6f%67%69%6e'), true)
  assert.equal(isAuthUrl('https://erp.example/jderest/v2/tokenrequest'), true)
  assert.equal(isAuthUrl('https://login.microsoftonline.com/common/oauth2/v2.0/token'), true)
  assert.equal(isAuthUrl('https://erp.example/api/orders/42'), false)
})

test('URL sanitization templates query values in semantic mode, preserves %20 in semantic+samples, masks high-entropy path segments, and truncates safely', () => {
  const raw = 'https://user:pass@app.example/items/550e8400-e29b-41d4-a716-446655440000/aB3dE9fG2hJ5kL8mN1pQ4rS7tU0vW/view?id=42&customer=Jane%20Lee&verification_code=999111&flag=true'

  const sem = sanitizeUrl(raw, { projection: 'semantic' })
  assert.ok(!sem.url.includes('user:pass@'), 'strips userinfo')
  assert.ok(sem.url.includes('/550e8400-e29b-41d4-a716-446655440000/'), 'preserves UUID segment')
  assert.ok(sem.url.includes('/[REDACTED:seg]/'), 'masks high-entropy path segment')
  assert.ok(sem.url.endsWith('?id=<num>&customer=<str>&verification_code=[REDACTED]&flag=<bool>'), `got ${sem.url}`)

  const samp = sanitizeUrl(raw, { projection: 'semantic+samples' })
  assert.ok(samp.url.endsWith('?id=42&customer=Jane%20Lee&verification_code=[REDACTED]&flag=true'), `preserves %20: got ${samp.url}`)

  // Safe head+tail truncation never splits %XX or UTF-16 surrogate pairs
  const withPct = 'a'.repeat(1535) + '%20' + 'b'.repeat(600) + '😀' + 'c'.repeat(510)
  const trunc = truncateHeadTail(withPct, 2048, 1536, 512)
  assert.ok(trunc.length <= 2049)
  assert.ok(!trunc.includes('%…'), 'did not split %20 at head')
  assert.ok(!trunc.includes('…20'), 'did not leave dangling hex digits')
  for (let i = 0; i < trunc.length; i++) {
    const code = trunc.charCodeAt(i)
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = trunc.charCodeAt(i + 1)
      assert.ok(next >= 0xdc00 && next <= 0xdfff, 'no lone high surrogate')
    }
  }
})

test('P1-5 valueless query params and query key names are templated/redacted in semantic & samples modes, and P2-3/P2-4 UUID gate & JSON key scrubbing hold', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF1234567890'
  const ghp = 'ghp_1234567890abcdefghij123456'

  const semJwt = sanitizeUrl(`https://h.example/p?${jwt}&a=b&plainflag`, { projection: 'semantic' })
  assert.equal(semJwt.url, 'https://h.example/p?[REDACTED]&a=<str>&<str>')

  const sampJwt = sanitizeUrl(`https://h.example/p?${jwt}&a=b`, { projection: 'semantic+samples' })
  assert.equal(sampJwt.url, 'https://h.example/p?[REDACTED]&a=b')

  const emailKey = sanitizeUrl('https://h.example/p?jane.doe%40example.com=1', { projection: 'semantic' })
  assert.equal(emailKey.url, 'https://h.example/p?<key>=<num>')

  const tokKey = sanitizeUrl(`https://h.example/p?${ghp}=`, { projection: 'semantic' })
  assert.equal(tokKey.url, 'https://h.example/p?[REDACTED]=')

  // P2-3: UUIDs, ISO dates, URLs rejected from SecretVault LRU token gate
  assert.equal(isTokenShaped('550e8400-e29b-41d4-a716-446655440000'), false, 'plain UUID rejected from vault LRU')
  assert.equal(isTokenShaped('2026-11-27T12:00:00.000Z'), false, 'ISO date rejected from vault LRU')
  assert.equal(isTokenShaped('https://portal.example/items/12345'), false, 'URL rejected from vault LRU')

  // P2-4: redactJsonValue scrubs data-like and vault map keys in samples mode
  const vault = new SecretVault()
  vault.addTrustedDrive('TypedVal9941')
  const { value } = redactJsonValue({ 'jane.doe@example.com': 'ok', TypedVal9941: 'x', safeField: 1 }, vault)
  const str = JSON.stringify(value)
  assert.ok(!str.includes('jane.doe@example.com'))
  assert.ok(!str.includes('TypedVal9941'))
  assert.match(str, /"<key>":"ok"/)
  assert.match(str, /"\[REDACTED:vault\]":"x"/)
  assert.match(str, /"safeField":1/)
})
