import { test } from 'node:test'
import assert from 'node:assert/strict'
import zlib from 'node:zlib'
import {
  classifyGraphqlQuery,
  decompressPrefix,
  extractSemantic,
} from '../src/extract.ts'
import { SecretVault } from '../src/redact.ts'

test('E1 AIS extractor captures formName, action, and formActions controlIDs without leaking free-text values', () => {
  const payload = JSON.stringify({
    formName: 'P0411_W0411A',
    version: 'ZJDE0001',
    formServiceAction: 'U',
    formActions: [
      { command: 'SetControlValue', controlID: '18', value: 'ACME Corp Secret Vendor Note' },
      { command: 'DoAction', controlID: '12' },
    ],
  })
  const res = extractSemantic({
    url: new URL('https://e1.example/jderest/v2/formservice'),
    sanitizedPath: '/jderest/v2/formservice',
    method: 'POST',
    effectiveMethod: 'POST',
    kind: 'http',
    rawHeaders: {},
    reqType: 'application/json',
    decodedBuf: Buffer.from(payload),
    bodyComplete: true,
    transport: 'complete',
    isWrite: true,
    isAuth: false,
    isLive: false,
    projection: 'semantic',
  })
  assert.equal(res.actions.length, 1)
  assert.equal(res.actions[0].family, 'e1-ais')
  assert.equal(res.actions[0].op, 'formservice:U')
  assert.equal(res.actions[0].resource, 'P0411_W0411A')
  assert.deepEqual(res.actions[0].details?.formActions, [
    { command: 'SetControlValue', controlID: '18' },
    { command: 'DoAction', controlID: '12' },
  ])
  assert.equal(res.reqBody, undefined, 'default semantic mode emits zero raw reqBody')
  assert.equal(res.reqOmitted, 'policy-profile')
  assert.ok(!JSON.stringify(res.actions).includes('ACME Corp'), 'no free-text values in semantic actions')
  assert.equal(res.bodyShape?.['formActions[].value'], 'string')
})

test('SharePoint extractor handles list/item override and marks $batch as opaque-batch', () => {
  const item = extractSemantic({
    url: new URL("https://tenant.sharepoint.com/_api/web/lists/getbytitle('Invoices')/items(42)"),
    sanitizedPath: "/_api/web/lists/getbytitle('Invoices')/items(42)",
    method: 'POST',
    effectiveMethod: 'DELETE',
    kind: 'http',
    hdr: { 'x-http-method': 'DELETE' },
    rawHeaders: { 'if-match': '*', 'x-requestdigest': 'tok' },
    reqType: 'application/json',
    decodedBuf: Buffer.from(JSON.stringify({ __metadata: { type: 'SP.Data.InvoicesListItem' } })),
    bodyComplete: true,
    transport: 'complete',
    isWrite: true,
    isAuth: false,
    isLive: false,
    projection: 'semantic',
  })
  assert.equal(item.actions[0].family, 'sharepoint')
  assert.equal(item.actions[0].op, 'sharepoint:DELETE')
  assert.equal(item.actions[0].details?.override, 'DELETE')
  assert.equal(item.actions[0].details?.hasIfMatch, true)
  assert.equal(item.actions[0].details?.metadataType, 'SP.Data.InvoicesListItem')
  assert.equal(item.completeness.extract, 'complete')

  const batch = extractSemantic({
    url: new URL('https://tenant.sharepoint.com/_api/$batch'),
    sanitizedPath: '/_api/$batch',
    method: 'POST',
    effectiveMethod: 'POST',
    kind: 'http',
    rawHeaders: { 'x-requestdigest': 'tok' },
    reqType: 'multipart/mixed',
    decodedBuf: Buffer.from('--batch_123\r\nDELETE /_api/web/items(1)'),
    bodyComplete: true,
    transport: 'complete',
    isWrite: true,
    isAuth: false,
    isLive: false,
    projection: 'semantic',
  })
  assert.equal(batch.actions[0].family, 'sharepoint')
  assert.equal(batch.actions[0].coverage, 'opaque-batch')
  assert.equal(batch.completeness.extract, 'opaque')
})

test('GraphQL strict token classifier handles comments, strings, duplicate operation names, and persisted queries', () => {
  assert.equal(classifyGraphqlQuery('# mutation Fake {}\nquery GetUser { user(note: "mutation {}") { id } }', 'GetUser').op, 'query')
  assert.equal(classifyGraphqlQuery('{ viewer { login } }').op, 'query')
  assert.equal(classifyGraphqlQuery('mutation DeleteInvoice($id: ID!) { deleteInvoice(id: $id) }', 'DeleteInvoice').op, 'mutation')
  assert.equal(classifyGraphqlQuery('query X { a } mutation X { b }', 'X').op, 'mixed', 'duplicate opName resolves to mixed')
  assert.equal(classifyGraphqlQuery('query A { a } mutation B { b }').op, 'mixed', 'multiple ops without opName resolve to mixed')

  const persisted = extractSemantic({
    url: new URL('https://app.example/graphql'),
    sanitizedPath: '/graphql',
    method: 'POST',
    effectiveMethod: 'POST',
    kind: 'http',
    rawHeaders: {},
    reqType: 'application/json',
    decodedBuf: Buffer.from(JSON.stringify({ operationName: 'ApprovePO', extensions: { persistedQuery: { sha256Hash: 'abc' } } })),
    bodyComplete: true,
    transport: 'complete',
    isWrite: true,
    isAuth: false,
    isLive: false,
    projection: 'semantic',
  })
  assert.equal(persisted.graphqlOp, 'persisted')
  assert.equal(persisted.actions[0].coverage, 'persisted-query-unknown')
})

test('SOAP extractor parses Body root QName and flags SOAPAction mismatch', () => {
  const xml = `<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><!-- comment --><soapenv:Body><ns:ApproveVoucher><id>42</id></ns:ApproveVoucher></soapenv:Body></soapenv:Envelope>`
  const res = extractSemantic({
    url: new URL('https://bssv.example/VoucherManager'),
    sanitizedPath: '/VoucherManager',
    method: 'POST',
    effectiveMethod: 'POST',
    kind: 'http',
    hdr: { soapaction: '"ReadVoucher"' },
    rawHeaders: {},
    reqType: 'text/xml',
    decodedBuf: Buffer.from(xml),
    bodyComplete: true,
    transport: 'complete',
    isWrite: true,
    isAuth: false,
    isLive: false,
    projection: 'semantic',
  })
  assert.equal(res.actions[0].family, 'soap')
  assert.equal(res.actions[0].op, 'soap:ns:ApproveVoucher')
  assert.equal(res.actions[0].details?.actionMismatch, true)
})

test('streaming decompressors cap 1 MiB gzip/deflate/br/zstd at 64 KiB and mark truncated prefixes as truncated (never decompress-err)', async () => {
  const big = Buffer.from(JSON.stringify({ items: Array.from({ length: 15000 }, (_, i) => ({ id: i, text: 'hello-world-payload-data-' + i })) }))
  assert.ok(big.length > 500_000)

  const cases: Array<[string, Buffer]> = [
    ['gzip', zlib.gzipSync(big)],
    ['deflate', zlib.deflateSync(big)],
    ['deflate', zlib.deflateRawSync(big)],
    ['br', zlib.brotliCompressSync(big)],
    ['zstd', zlib.zstdCompressSync(big)],
  ]

  for (const [enc, compressed] of cases) {
    // Full compressed payload decompressing to > 64 KiB -> capped at 64 KiB, decode: 'truncated'
    const fullCap = await decompressPrefix(compressed, enc, true)
    assert.equal(fullCap.ok, true, `${enc} full 1MiB should succeed with cap`)
    assert.equal(fullCap.decodeComplete, false, `${enc} >64KiB is not decodeComplete`)
    assert.equal(fullCap.decode, 'truncated', `${enc} >64KiB must be decode: truncated`)
    assert.equal(fullCap.buf.length, 65_536, `${enc} capped at exact 64 KiB`)

    // Truncated compressed prefix (!bodyComplete) -> decode: 'truncated', NEVER decompress-err
    const partial = compressed.subarray(0, Math.min(2048, Math.floor(compressed.length / 2)))
    const truncRes = await decompressPrefix(partial, enc, false)
    assert.equal(truncRes.ok, true, `${enc} truncated prefix must not fail as decompress-err`)
    assert.equal(truncRes.decodeComplete, false)
    assert.equal(truncRes.decode, 'truncated')
  }

  // Corrupt complete gzip (bodyComplete === true) -> decode: 'error'
  const corrupt = await decompressPrefix(Buffer.from('not-actually-gzip-data'), 'gzip', true)
  assert.equal(corrupt.ok, false)
  assert.equal(corrupt.decode, 'error')
})

test('semantic+samples emits redacted reqBody with JSON.rawJSON numbers and scrubs vault secrets', () => {
  const vault = new SecretVault()
  vault.addTrustedDrive('SuperSecret99')
  const body = '{"amount":12.50,"note":"ref SuperSecret99","apiKey":"k123"}'
  const res = extractSemantic({
    url: new URL('https://app.example/api/pay'),
    sanitizedPath: '/api/pay',
    method: 'POST',
    effectiveMethod: 'POST',
    kind: 'http',
    rawHeaders: {},
    reqType: 'text/plain', // spoofed Content-Type: JSON still parsed!
    decodedBuf: Buffer.from(body),
    bodyComplete: true,
    transport: 'complete',
    isWrite: true,
    isAuth: false,
    isLive: false,
    projection: 'semantic+samples',
    vault,
  })
  assert.equal(res.reqBody, '{"amount":12.50,"note":"ref [REDACTED:vault]","apiKey":"[REDACTED]"}')
  assert.equal(res.vaultRedactions, 1)
})
