import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { once } from 'node:events'
import type { AddressInfo } from 'node:net'
import { blocklist, isBlocked, loadBlocklists } from '../src/blocklists.ts'

test('blocklists are one in-memory set, replaced only after every source loads; a failed fetch, an empty or garbled list, or a set under half the last keeps the last set', async t => {
  let status = 503, text = '# threats\n\n Bad.Example. \r\n'
  const server = http.createServer((req, res) => res.writeHead(req.url === '/second' ? status : 200).end(req.url === '/second' ? 'second.example\n' : text)).listen(0, '127.0.0.1')
  t.after(() => server.close())
  await once(server, 'listening')
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  process.env.BROWSER_BLOCKLISTS = `${origin}/first \n ${origin}/second`
  assert.equal(blocklist, undefined)
  await loadBlocklists()
  assert.equal(blocklist, undefined)
  status = 200
  await loadBlocklists()
  assert.equal(blocklist!.size, 2)
  for (const host of ['bad.example', 'a.bad.example', 'A.BAD.EXAMPLE.', 'second.example']) assert.equal(isBlocked(host), true)
  for (const host of ['example', 'notbad.example', 'good.example']) assert.equal(isBlocked(host), false)
  text = 'new.example\n'
  status = 503
  await loadBlocklists()
  assert.equal(isBlocked('bad.example'), true)
  assert.equal(isBlocked('new.example'), false)
  status = 200
  await loadBlocklists()
  assert.equal(isBlocked('bad.example'), false)
  assert.equal(isBlocked('new.example'), true)
  for (const garbage of ['', '# nothing\n\n', '<!doctype html>\n<title>Sign in to Wi-Fi</title>\n']) {
    text = garbage
    await loadBlocklists()
    assert.equal(isBlocked('new.example'), true, `${JSON.stringify(garbage)} keeps the last set`)
  }
  text = Array.from({ length: 10 }, (_, i) => `d${i}.example`).join('\n')
  await loadBlocklists()
  assert.equal(blocklist!.size, 11)
  text = 'd0.example\n'
  await loadBlocklists()
  assert.equal(blocklist!.size, 11, 'a set under half the size of the one in use keeps that one')
})
