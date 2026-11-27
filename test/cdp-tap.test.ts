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

  tap.seal()
  const entries = tap.entries.filter((e): e is CdpEntry => e.rec !== '_tap.summary')
  assert.ok(entries.some(e => e.method === '_tap.oversized' && e.severity === 'high' && e.summary?.bytes === bigPayload.length))
  assert.ok(entries.some(e => e.method === '_tap.disabled' && e.severity === 'high'))
  const summary = tap.entries.find(e => e.rec === '_tap.summary') as any
  assert.equal(summary.methodCounts['_playwright.injectedScript'], 1)
  assert.equal(summary.tapDisabledCount, 1)
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

  // Drive vault tap
  const vault = new SecretVault()
  const drive = createDriveVaultTap(vault)
  drive.feed(encodeWsFrame(Buffer.from(JSON.stringify({ id: 1, method: 'Input.insertText', params: { text: '654321' } }))))
  drive.close()
  assert.equal(vault.scrub('code=654321').text, 'code=[REDACTED:vault]')
})
