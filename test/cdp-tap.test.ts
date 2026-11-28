import { test } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { CdpSessionTap, WsFrameParser, createDriveVaultTap, type CdpEntry } from '../src/cdp-tap.ts'
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

test('WsFrameParser handles 1-byte splits, FIN=0 fragmentation with interleaved Ping, >64 KiB head-only unmask, and never mutates input', () => {
  const msgs: any[] = []
  const errors: string[] = []
  const parser = new WsFrameParser(m => msgs.push(m), e => errors.push(e))

  const f1 = encodeWsFrame(Buffer.from('{"id":1,"method":"Page.na'), { fin: false, opcode: 0x1 })
  const ping = encodeWsFrame(Buffer.from('hi'), { fin: true, opcode: 0x9 })
  const f2 = encodeWsFrame(Buffer.from('vigate","params":{"url":"https://a.example/"}}'), { fin: true, opcode: 0x0 })
  const big = encodeWsFrame(Buffer.from(JSON.stringify({ id: 2, method: 'Runtime.evaluate', params: { expression: 'x'.repeat(70_000) } })))

  const wire = Buffer.concat([f1, ping, f2, big])
  const snapshot = Buffer.from(wire)
  for (let i = 0; i < wire.length; i++) parser.feed(wire.subarray(i, i + 1))

  assert.ok(wire.equals(snapshot))
  assert.equal(errors.length, 0)
  assert.equal(msgs.length, 2)
  assert.equal(msgs[0].head.toString(), '{"id":1,"method":"Page.navigate","params":{"url":"https://a.example/"}}')
  assert.equal(msgs[1].truncated, true)
  assert.equal(msgs[1].head.length, 65_536)
})

test('CDP tap fails closed via onError on protocol violations and flags oversized frames as high severity', () => {
  const tap = new CdpSessionTap({ isLive: () => false, coalesceMs: 10 })
  const errors: string[] = []

  const c1 = tap.attachConnection({ onError: r => errors.push(r) })
  const bigPayload = Buffer.from(JSON.stringify({ id: 1, method: 'Runtime.evaluate', params: { expression: 'y'.repeat(70_000) } }))
  c1.feed(encodeWsFrame(bigPayload))

  const c2 = tap.attachConnection({ onError: r => errors.push(r) })
  c2.feed(encodeWsFrame(Buffer.from('{"method":"Page.reload"}'), { rsv: 0x40 }))

  const c3 = tap.attachConnection({ onError: r => errors.push(r) })
  c3.feed(encodeWsFrame(Buffer.from('{"method":"Page.reload"}'), { mask: false }))

  tap.seal()
  assert.equal(errors.length, 2, 'non-zero RSV and unmasked frame both fail closed via onError')
  const entries = tap.entries.filter((e): e is CdpEntry => e.rec !== '_tap.summary')
  assert.ok(entries.some(e => e.method === '_tap.oversized' && e.severity === 'high' && e.summary?.bytes === bigPayload.length))
  assert.ok(!entries.some(e => e.method === '_tap.disabled'), 'no _tap.disabled passthrough')
})

test('CdpSessionTap emits uniform fnLen/fnHash64/argCount, input length-only, names-only storage/headers, recursion limit, coalescing, and duplicate-key ambiguity', () => {
  let uploadTriggered = 0
  const tap = new CdpSessionTap({
    isLive: () => false,
    coalesceMs: 40,
    onFileUpload: () => { uploadTriggered++ },
  })
  const conn = tap.attachConnection()
  const send = (obj: unknown) => conn.feed(encodeWsFrame(Buffer.from(JSON.stringify(obj))))

  send({
    id: 1, sessionId: 's1', method: 'Runtime.callFunctionOn',
    params: { functionDeclaration: '(u, ...a) => u.evaluate(...a)', arguments: [{ value: 1 }, { value: 'secret' }] },
  })
  send({ id: 2, sessionId: 's1', method: 'Input.insertText', params: { text: 'TopSecretPassword' } })
  send({ id: 3, sessionId: 's1', method: 'DOM.setFileInputFiles', params: { files: ['/tmp/invoice.pdf'] } })
  send({ id: 4, sessionId: 's1', method: 'Network.setExtraHTTPHeaders', params: { headers: { Authorization: 'Bearer secret123', 'X-Trace': '1' } } })
  send({ id: 5, sessionId: 's1', method: 'DOMStorage.setDOMStorageItem', params: { key: 'auth_state', value: 'raw-token-value' } })
  send({ id: 6, sessionId: 's1', method: 'Page.navigate', params: { url: 'javascript:alert(1)' } })
  send({ id: 7, sessionId: 's1', method: 'DOM.setAttributeValue', params: { name: 'onclick', value: 'steal()' } })

  const inner = JSON.stringify({ id: 8, method: 'Page.reload' })
  send({ id: 9, method: 'Target.sendMessageToTarget', params: { sessionId: 'nested-1', message: inner } })
  const deep3 = JSON.stringify({ method: 'Target.sendMessageToTarget', params: { message: JSON.stringify({ method: 'Target.sendMessageToTarget', params: { message: inner } }) } })
  send({ id: 10, method: 'Target.sendMessageToTarget', params: { message: deep3 } })

  for (let i = 0; i < 3; i++) {
    send({ id: 20 + i, sessionId: 's1', method: 'Input.dispatchMouseEvent', params: { type: 'mousePressed', button: 'left', x: 100, y: 200 } })
  }

  conn.feed(encodeWsFrame(Buffer.from('{"id":30,"method":"Page.reload","method":"Runtime.evaluate","params":{"expression":"1+1"}}')))
  tap.seal()

  assert.equal(uploadTriggered, 1)
  const entries = tap.entries.filter((e): e is CdpEntry => e.rec !== '_tap.summary')

  const callFn = entries.find(e => e.method === 'Runtime.callFunctionOn')!
  assert.equal(typeof callFn.summary?.fnLen, 'number')
  assert.equal(typeof callFn.summary?.fnHash64, 'string')
  assert.equal(callFn.summary?.argCount, 2)
  assert.equal(callFn.summary?.wrapper, undefined)
  assert.ok(!JSON.stringify(callFn).includes('secret'))

  const ins = entries.find(e => e.method === 'Input.insertText')!
  assert.deepEqual(ins.summary, { len: 'TopSecretPassword'.length })
  assert.ok(!JSON.stringify(ins).includes('TopSecretPassword'))

  const hdrs = entries.find(e => e.method === 'Network.setExtraHTTPHeaders')!
  assert.deepEqual(hdrs.summary, { headerNames: ['Authorization', 'X-Trace'] })
  assert.ok(!JSON.stringify(hdrs).includes('secret123'))

  const domSt = entries.find(e => e.method === 'DOMStorage.setDOMStorageItem')!
  assert.deepEqual(domSt.summary, { key: 'auth_state' })
  assert.ok(!JSON.stringify(domSt).includes('raw-token-value'))

  assert.equal(entries.find(e => e.method === 'Page.navigate')!.severity, 'high')
  assert.equal(entries.find(e => e.method === 'DOM.setAttributeValue')!.severity, 'high')
  assert.equal(entries.find(e => e.method === 'Input.dispatchMouseEvent')!.count, 3)
  assert.ok(entries.some(e => e.ambiguous === true && e.severity === 'high'))
  const summary = tap.entries.find(e => e.rec === '_tap.summary') as any
  assert.equal(summary.depthLimited, 1)
})

test('drive tap records commands in CDP log with live: true AND populates SecretVault without leaking typed secrets', () => {
  const vault = new SecretVault()
  const tap = new CdpSessionTap({ vault, isLive: () => false, coalesceMs: 10 })
  const drive = tap.attachConnection({ live: true, driveVault: true })
  drive.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 1, method: 'Input.insertText', params: { text: '654321' } }))))
  drive.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 2, method: 'Page.navigate', params: { url: 'https://app.example/pay?code=654321' } }))))
  drive.close()

  // Separate drive-only vault tap also keeps isolated buffers
  const d2 = createDriveVaultTap(vault)
  d2.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 1, method: 'Input.insertText', params: { text: 'AlphaPass' } }))))
  d2.close()

  tap.seal()
  const entries = tap.entries.filter((e): e is CdpEntry => e.rec !== '_tap.summary')
  assert.ok(entries.length >= 2)
  assert.ok(entries.every(e => e.live === true), 'every /view/drive entry carries live: true')
  assert.ok(!JSON.stringify(entries).includes('654321'), 'typed secret never appears in CDP log')
  assert.equal(vault.scrub('code=654321 pw=AlphaPass').text, 'code=[REDACTED:vault] pw=[REDACTED:vault]')
})

test('nav URL sanitization and method/entry bounds prevent secret leaks and memory growth', () => {
  const vault = new SecretVault()
  vault.addTrustedDrive('MixedTenant99')
  vault.addTrustedDrive('MyMimeSec')
  vault.addTrustedDrive('MySecScheme')

  const tap = new CdpSessionTap({ vault, isLive: () => false, coalesceMs: 10, maxEntries: 50 })
  const conn = tap.attachConnection()

  const navInputs = [
    '\u0001java\tscript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'data:application/vnd.MyMimeSec+xml,abc',
    'https://MixedTenant99.example/secret?token=abc',
    'MySecScheme:payload',
    'blob:https://MixedTenant99.example/uuid',
  ]
  for (const [i, u] of navInputs.entries()) {
    conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: i + 1, method: 'Page.navigate', params: { url: u } }))))
  }
  conn.feed(encodeWsFrame(Buffer.from('not-valid-json{{{')))
  for (let i = 0; i < 300; i++) {
    conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 100 + i, method: `Custom.Method${i}` }))))
  }
  conn.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 900, method: '__proto__' }))))
  tap.seal()

  const json = JSON.stringify(tap.entries).toLowerCase()
  for (const secret of ['mixedtenant99', 'mymimesec', 'mysecscheme', '<script>']) {
    assert.ok(!json.includes(secret), `CDP log leaked ${secret}`)
  }
  const summary = tap.entries.find(e => e.rec === '_tap.summary') as any
  assert.ok(Object.keys(summary.methodCounts).length <= 257)
  assert.equal(summary.methodCounts._unparsed, 1)
})
