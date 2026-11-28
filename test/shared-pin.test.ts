import { test } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const sharedDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/shared')
const sumsPath = path.join(sharedDir, 'SHA256SUMS')

test('vendored src/shared/ files match pinned SHA-256 digests with no unpinned drift', () => {
  const raw = fs.readFileSync(sumsPath, 'utf8').trim()
  const lines = raw.split(/\r?\n/).filter(Boolean)
  assert.ok(lines.length >= 2, 'SHA256SUMS must pin classify.ts and redact.ts')

  const pinned = new Map<string, string>()
  for (const line of lines) {
    const match = /^([0-9a-f]{64})\s{2}(.+)$/.exec(line)
    assert.ok(match, `malformed SHA256SUMS line: ${line}`)
    pinned.set(match[2], match[1])
  }

  for (const required of ['classify.ts', 'redact.ts']) {
    assert.ok(pinned.has(required), `SHA256SUMS missing required entry: ${required}`)
  }

  const actualTsFiles = fs.readdirSync(sharedDir).filter(f => f.endsWith('.ts')).sort()
  assert.deepEqual(
    actualTsFiles,
    [...pinned.keys()].sort(),
    'src/shared/*.ts files must match SHA256SUMS entries exactly',
  )

  for (const [file, expectedHex] of pinned) {
    const content = fs.readFileSync(path.join(sharedDir, file))
    const actualHex = crypto.createHash('sha256').update(content).digest('hex')
    assert.equal(
      actualHex,
      expectedHex,
      `vendored src/shared/${file} drifted from pinned sha256; run scripts/sync-shared.sh from rollforward instead of editing locally`,
    )
  }
})
