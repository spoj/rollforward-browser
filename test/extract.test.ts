import { test } from 'node:test'
import assert from 'node:assert/strict'
import zlib from 'node:zlib'
import {
  classifyGraphqlQuery,
  decompressPrefix,
  extractSemantic,
  normalizeContentType,
} from '../src/extract.ts'

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
  })
  assert.equal(res.actions.length, 1)
  assert.equal(res.actions[0].family, 'e1-ais')
  assert.equal(res.actions[0].op, 'formservice:U')
  assert.equal(res.actions[0].resource, 'P0411_W0411A')
  assert.deepEqual(res.actions[0].details?.formActions, [
    { command: 'SetControlValue', controlID: '18' },
    { command: 'DoAction', controlID: '12' },
  ])
  assert.equal(res.reqOmitted, 'policy-profile')
  assert.ok(!JSON.stringify(res.actions).includes('ACME Corp'))
  assert.equal(res.bodyShape?.['formActions[].value'], 'string')

  // Browser-only body-shape E1 detection still works on non-/jderest/ paths
  const byShape = extractSemantic({
    url: new URL('https://e1.example/custom/endpoint'),
    sanitizedPath: '/custom/endpoint',
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
  })
  assert.equal(byShape.actions[0].family, 'e1-ais')
  assert.equal(byShape.actions[0].op, 'ais:U')
  assert.equal(byShape.actions[0].resource, 'P0411_W0411A')
})

test('SharePoint extractor handles overrides, sanitizedPath offsets, strong If-Match, and marks $batch opaque', () => {
  const item = extractSemantic({
    url: new URL("https://tenant.sharepoint.com/sites/aB3dE9fG2hJ5kL8mN1pQ4rS7tU0vW/_api/web/lists/getbytitle('Invoices')/items(42)"),
    sanitizedPath: "/sites/[REDACTED:seg]/_api/web/lists/getbytitle('Invoices')/items(42)",
    method: 'POST',
    effectiveMethod: 'DELETE',
    kind: 'http',
    hdr: { 'x-http-method': 'DELETE' },
    rawHeaders: { 'if-match': '"etag-1"', 'x-requestdigest': 'tok' },
    reqType: 'application/json',
    decodedBuf: Buffer.from(JSON.stringify({ __metadata: { type: 'SP.Data.InvoicesListItem' } })),
    bodyComplete: true,
    transport: 'complete',
    isWrite: true,
    isAuth: false,
    isLive: false,
  })
  assert.equal(item.actions[0].family, 'sharepoint')
  assert.equal(item.actions[0].op, 'sharepoint:DELETE')
  assert.equal(item.actions[0].resource, "/_api/web/lists/getbytitle('Invoices')/items(42)")
  assert.equal(item.actions[0].details?.override, 'DELETE')
  assert.equal(item.actions[0].details?.hasIfMatch, true)
  assert.equal(item.actions[0].details?.metadataType, 'SP.Data.InvoicesListItem')

  const wildcard = extractSemantic({
    url: new URL("https://tenant.sharepoint.com/_api/web/lists/getbytitle('Invoices')/items(42)"),
    sanitizedPath: "/_api/web/lists/getbytitle('Invoices')/items(42)",
    method: 'POST',
    effectiveMethod: 'DELETE',
    kind: 'http',
    hdr: { 'x-http-method': 'DELETE' },
    rawHeaders: { 'if-match': '*', 'x-requestdigest': 'tok' },
    reqType: 'application/json',
    decodedBuf: Buffer.from('{}'),
    bodyComplete: true,
    transport: 'complete',
    isWrite: true,
    isAuth: false,
    isLive: false,
  })
  assert.equal(wildcard.actions[0].details?.hasIfMatch, false)

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
  })
  assert.equal(batch.actions[0].coverage, 'opaque-batch')
  assert.equal(batch.completeness.extract, 'opaque')
})

test('GraphQL classifier handles comments, strings, fragments, duplicate ops, persisted queries, and >16 batch late mutation', () => {
  assert.equal(classifyGraphqlQuery('# mutation Fake {}\nquery GetUser { user(note: "mutation {}") { id } }', 'GetUser').op, 'query')
  assert.equal(classifyGraphqlQuery('fragment F on User { id }\nmutation DeleteInvoice($id: ID!) { deleteInvoice(id: $id) }', 'DeleteInvoice').op, 'mutation')
  assert.equal(classifyGraphqlQuery('{ viewer { login } }').op, 'query')
  assert.equal(classifyGraphqlQuery('query X { a } mutation X { b }', 'X').op, 'mixed')
  assert.equal(classifyGraphqlQuery('query A { a } mutation B { b }').op, 'mixed')

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
  })
  assert.equal(persisted.graphqlOp, 'persisted')
  assert.equal(persisted.actions[0].coverage, 'persisted-query-unknown')

  const batch = Array.from({ length: 18 }, (_, i) => ({
    query: i === 17 ? 'mutation LateWrite { doWrite }' : `query Q${i} { ok }`,
  }))
  const gql = extractSemantic({
    url: new URL('https://app.example/graphql'),
    sanitizedPath: '/graphql',
    method: 'POST',
    effectiveMethod: 'POST',
    kind: 'http',
    rawHeaders: {},
    reqType: 'application/json',
    decodedBuf: Buffer.from(JSON.stringify(batch)),
    bodyComplete: true,
    transport: 'complete',
    isWrite: true,
    isAuth: false,
    isLive: false,
  })
  assert.equal(gql.graphqlOp, 'mixed')
  assert.equal(gql.actions.length, 16)
})

test('SOAP extractor parses Body root QName, flags SOAPAction mismatch, and stays linear on adversarial input', () => {
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
  })
  assert.equal(res.actions[0].family, 'soap')
  assert.equal(res.actions[0].op, 'soap:ns:ApproveVoucher')
  assert.equal(res.actions[0].details?.actionMismatch, true)

  for (const adversarial of ['<Body '.repeat(10_922), '<!--'.repeat(16_384)]) {
    const t0 = performance.now()
    extractSemantic({
      url: new URL('https://bssv.example/VoucherManager'),
      sanitizedPath: '/VoucherManager',
      method: 'POST',
      effectiveMethod: 'POST',
      kind: 'http',
      hdr: { soapaction: '"TestAction"' },
      rawHeaders: {},
      reqType: 'text/xml',
      decodedBuf: Buffer.from(adversarial),
      bodyComplete: true,
      transport: 'complete',
      isWrite: true,
      isAuth: false,
      isLive: false,
    })
    assert.ok(performance.now() - t0 < 20)
  }
})

test('sync decompressPrefix decodes gzip/deflate/br within 64 KiB and omits oversized, corrupt, or unsupported encodings as encoded', () => {
  const small = Buffer.from(JSON.stringify({ ok: true, id: 7 }))
  for (const [enc, compressed] of [
    ['gzip', zlib.gzipSync(small)],
    ['deflate', zlib.deflateSync(small)],
    ['br', zlib.brotliCompressSync(small)],
  ] as const) {
    const res = decompressPrefix(compressed, enc, true)
    assert.equal(res.ok, true, enc)
    assert.equal(res.decodeComplete, true, enc)
    assert.equal(res.buf.toString(), small.toString(), enc)
  }

  // >64 KiB decompressed output fails closed with reason: 'encoded'
  const big = Buffer.from('x'.repeat(100_000))
  const over = decompressPrefix(zlib.gzipSync(big), 'gzip', true)
  assert.equal(over.ok, false)
  assert.equal(over.reason, 'encoded')

  // Corrupt or unsupported encoding fails closed with reason: 'encoded'
  assert.equal(decompressPrefix(Buffer.from('not-gzip'), 'gzip', true).reason, 'encoded')
  assert.equal(decompressPrefix(small, 'zstd', true).reason, 'encoded')

  // Truncated complete gzip trailer fails strict EOF
  const gz = zlib.gzipSync(small)
  assert.equal(decompressPrefix(gz.subarray(0, gz.length - 4), 'gzip', true).ok, false)

  // normalizeContentType allows standard MIME types and maps others to 'other'
  assert.equal(normalizeContentType('application/json; charset=utf-8'), 'application/json')
  assert.equal(normalizeContentType('x-custom/secret-subtype'), 'other')
})
