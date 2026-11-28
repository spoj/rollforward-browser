import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  SecretVault,
  buildBodyShape,
  isAuthUrl,
  isSensitiveKey,
  isTokenShaped,
  parseJsonSafe,
  sanitizeUrl,
  scrubDeep,
  truncateUtf8HeadTail,
} from '../src/redact.ts'

test('sensitive key classification preserves ordinary business fields and catches credentials + compound suffixes', () => {
  for (const k of ['AuthorizationNumber', 'PrimaryKey', 'TrainingSession', 'PassFail', 'PostalCode', 'Secretary', 'CreditLimit', 'AccountNumber', 'OrderCode', 'InvoiceKey']) {
    assert.equal(isSensitiveKey(k), false, `expected ${k} to be preserved`)
  }
  for (const k of [
    'Authorization', 'key', 'code', 'pin', 'pass', 'session', 'auth', 'sig',
    'apiKey', 'FormDigestValue', 'X-RequestDigest', 'passcode', 'verificationCode',
    'smsCode', 'authCode', 'userPass', 'userPin', 'sessionKey', 'signingKey',
    'token', 'client_secret', 'access_token', 'refresh_token', 'session_id',
    'sessionId', 'jas_token', 'code_verifier', 'password', 'xsrf', 'csrf', 'cvv', 'ssn',
    '\u212Aey', '\u212APassword',
  ]) {
    assert.equal(isSensitiveKey(k), true, `expected ${k} to be redacted`)
  }
})

test('parseJsonSafe detects duplicate keys including unicode-escaped duplicates', () => {
  const parsed = parseJsonSafe('{"a":1,"\\u0061":2}')
  assert.equal(parsed.ok, true)
  if (parsed.ok) assert.equal(parsed.dupKeys, true)
})

test('bodyShape collapses arrays, strips scalar values, and masks data-like map keys', () => {
  const doc = {
    formName: 'P0411_W0411A',
    items: [{ amount: 100.5, active: true }, { amount: 200.0, active: false }],
    byEmail: { 'jane.doe@example.com': { total: 5 } },
    byUuid: { '550e8400-e29b-41d4-a716-446655440000': 'ok' },
    byNum: { '123456': 'row' },
    byLong: { ['a'.repeat(33)]: 'val' },
  }
  const shape = buildBodyShape(doc)
  assert.equal(shape['formName'], 'string')
  assert.equal(shape['items[].amount'], 'number')
  assert.equal(shape['items[].active'], 'boolean')
  assert.equal(shape['byEmail.<key>.total'], 'number')
  assert.equal(shape['byUuid.<key>'], 'string')
  assert.equal(shape['byNum.<key>'], 'string')
  assert.equal(shape['byLong.<key>'], 'string')
  const serialized = JSON.stringify(shape)
  for (const leak of ['jane.doe@example.com', '550e8400', '123456', 'P0411_W0411A']) {
    assert.ok(!serialized.includes(leak), `leaked ${leak}`)
  }
})

test('SecretVault two-pool isolation prevents cookie poisoning and preserves trusted drive/header secrets under LRU flood', () => {
  const vault = new SecretVault()
  assert.equal(vault.addTrustedHeader('HeaderSecret-9988'), true)

  const drive = vault.createDriveBuffer()
  for (const ch of '482919') drive.onEvent('Input.dispatchKeyEvent', { type: 'keyDown', key: ch, text: ch })
  drive.onEvent('Input.dispatchKeyEvent', { type: 'rawKeyDown', key: 'Backspace' })
  drive.onEvent('Input.dispatchKeyEvent', { type: 'keyDown', key: '7', text: '7' })
  drive.onEvent('Input.dispatchKeyEvent', { type: 'rawKeyDown', key: 'Enter' })

  drive.onEvent('Input.insertText', { text: 'aborted' })
  drive.onEvent('Input.dispatchKeyEvent', { type: 'rawKeyDown', key: 'ArrowLeft' })
  drive.onEvent('Input.dispatchKeyEvent', { type: 'rawKeyDown', key: 'Enter' })
  assert.equal(vault.scrub('aborted').count, 0)

  drive.onEvent('Input.insertText', { text: 'HumanPass!2026' })
  drive.onEvent('Input.dispatchMouseEvent', { type: 'mousePressed' })

  // Numeric/UUID/ISO/URL values must not enter LRU
  for (const nonToken of ['98765432', '98765432109876543210', '1234567890123456.78', '550e8400-e29b-41d4-a716-446655440000', '2026-11-27T12:00:00.000Z', 'https://portal.example/items/12345']) {
    assert.equal(isTokenShaped(nonToken), false)
  }
  vault.ingestRequestHeaders({ cookie: 'z=98765432' })
  assert.equal(vault.scrub('AccountNumber=98765432').text, 'AccountNumber=98765432')

  // Flood LRU with 2,000 high-entropy cookies; trusted secrets must survive
  for (let i = 0; i < 2000; i++) {
    const tok = `c${i}_` + Buffer.from(`random-cookie-payload-${i}-!@#$%^&*()`).toString('base64url')
    vault.ingestSetCookie(`c${i}=${tok}; Path=/`)
  }
  assert.equal(vault.scrub('otp=482917').text, 'otp=[REDACTED:vault]')
  assert.equal(vault.scrub('pw=HumanPass%212026').text, 'pw=[REDACTED:vault]')
  assert.equal(vault.scrub('hdr=HeaderSecret-9988').text, 'hdr=[REDACTED:vault]')
})

test('isAuthUrl recognizes auth hosts, callbacks, dot segments, percent-encoding, and matrix params', () => {
  assert.equal(isAuthUrl('https://erp.example/jderest/v2/formservice;x=/login'), false)
  assert.equal(isAuthUrl('https://erp.example/jderest/v2/formservice;x=%2Flogin'), false)
  assert.equal(isAuthUrl('https://erp.example/app;v=1/login'), true)
  assert.equal(isAuthUrl('https://erp.example/sso/callback'), true)
  assert.equal(isAuthUrl('https://login.microsoftonline.com./common/foo'), true)
  assert.equal(isAuthUrl('https://erp.example/foo/../login'), true)
  assert.equal(isAuthUrl('https://erp.example/%6c%6f%67%69%6e'), true)
  assert.equal(isAuthUrl('https://erp.example/jderest/v2/tokenrequest'), true)
  assert.equal(isAuthUrl('https://erp.example/api/orders/42'), false)
})

test('table-driven no-secret-in-output: secrets never survive URL sanitization or exit scrubDeep', () => {
  const vault = new SecretVault()
  vault.addTrustedHeader('HdrTok!9988')
  vault.addTrustedDrive('MixedTenant99')
  vault.addTrustedDrive('739104')

  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF1234567890'
  const ghp = 'ghp_1234567890abcdefghij123456'

  const cases: Array<{ name: string; secret: string; output: unknown }> = [
    {
      name: 'userinfo + sensitive query + high-entropy path segment',
      secret: 'user:pass',
      output: sanitizeUrl('https://user:pass@app.example/items/aB3dE9fG2hJ5kL8mN1pQ4rS7tU0vW/view?verification_code=999111'),
    },
    {
      name: 'valueless JWT query param',
      secret: jwt,
      output: sanitizeUrl(`https://h.example/p?${jwt}&a=b`),
    },
    {
      name: 'GitHub PAT in query key',
      secret: ghp,
      output: sanitizeUrl(`https://h.example/p?${ghp}=1`),
    },
    {
      name: 'email in query key',
      secret: 'jane.doe',
      output: sanitizeUrl('https://h.example/p?jane.doe%40example.com=1'),
    },
    {
      name: 'vaulted mixed-case hostname lowercased by URL.parse',
      secret: 'mixedtenant99',
      output: scrubDeep(sanitizeUrl('https://MixedTenant99.example/api'), vault),
    },
    {
      name: 'vaulted OTP and URL-encoded header secret inside nested record keys & values',
      secret: '739104',
      output: scrubDeep({ nested: { 'k-739104': 'ref=739104', hdr: 'HdrTok%219988' } }, vault),
    },
    {
      name: 'URL-encoded header secret in nested record',
      secret: 'HdrTok',
      output: scrubDeep({ err: 'failed with HdrTok%219988' }, vault),
    },
  ]

  for (const c of cases) {
    const json = JSON.stringify(c.output).toLowerCase()
    assert.ok(!json.includes(c.secret.toLowerCase()), `case "${c.name}" leaked "${c.secret}" in ${json}`)
  }

  // UUID path segment preserved and UTF-8 truncation never splits %XX or surrogate pairs
  const sem = sanitizeUrl('https://app.example/items/550e8400-e29b-41d4-a716-446655440000?id=42&flag=true')
  assert.ok(sem.url.includes('/550e8400-e29b-41d4-a716-446655440000'))
  assert.ok(sem.url.endsWith('?id=<num>&flag=<bool>'))

  const withPct = 'a'.repeat(1535) + '%20' + 'b'.repeat(600) + '😀' + 'c'.repeat(510)
  const trunc = truncateUtf8HeadTail(withPct, 2048, 1536, 509)
  assert.ok(Buffer.byteLength(trunc, 'utf8') <= 2048)
  assert.ok(!trunc.includes('%…') && !trunc.includes('…20'))
})
