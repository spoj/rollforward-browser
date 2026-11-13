import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import net from 'node:net'
import { chromium } from 'playwright-core'

const port = 8799
const keys = ['first-secret', 'second-longer-secret']
const api = async (key: string, method: string, path: string, body?: unknown) => {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers: { authorization: `Bearer ${key}` }, body: body === undefined ? body : JSON.stringify(body) })
  return { status: res.status, body: await res.json() }
}

test('each client sees, uses and collects only its own sessions, including closed ones and every websocket', async t => {
  const service = spawn('node', ['src/server.ts'], { env: { ...process.env, BROWSER_PORT: String(port), BROWSER_KEYS: `first:${keys[0]} \n second-client:${keys[1]}`, BROWSER_KEY: 'ignored', BROWSER_BLOCKLISTS: '' }, stdio: ['ignore', 'pipe', 'inherit'] })
  t.after(() => service.kill())
  await Promise.race([once(service.stdout!, 'data'), once(service, 'exit').then(() => { throw new Error('service exited') })])
  assert.equal((await api('ignored', 'GET', '/sessions')).status, 401)
  assert.equal((await api('bad', 'GET', '/sessions')).status, 401)
  const opened = await Promise.all(keys.map(key => api(key, 'POST', '/sessions', { site: { hosts: [] } })))
  for (const result of opened) assert.equal(result.status, 201)
  for (const [i, key] of keys.entries()) {
    const own = opened[i].body, other = opened[1 - i].body
    assert.deepEqual((await api(key, 'GET', '/sessions')).body.map((s: any) => s.id), [own.id])
    for (const [method, rest, body] of [
      ['DELETE', '', undefined], ['GET', '/log', undefined], ['GET', '/view', undefined], ['GET', '/page', undefined],
      ['GET', '/screenshot', undefined], ['PUT', '/hosts', { hosts: ['stolen.example'] }], ['POST', '/reload', undefined],
      ['GET', '/files/tmp/x', undefined], ['PUT', '/files/tmp/x', 'stolen'],
    ] as const) assert.deepEqual(await api(key, method, `/sessions/${other.id}${rest}`, body), { status: 404, body: { error: 'no such session' } })
    for (const rest of ['/cdp', '/view/watch', '/view/drive']) {
      const socket = net.connect(port, '127.0.0.1')
      socket.write(`GET /sessions/${other.id}${rest} HTTP/1.1\r\nhost: localhost\r\nconnection: upgrade\r\nupgrade: websocket\r\nauthorization: Bearer ${key}\r\n\r\n`)
      assert.match(Buffer.concat(await socket.toArray()).toString(), /^HTTP\/1.1 404 Not Found/)
    }
    const browser = await chromium.connectOverCDP(`ws://127.0.0.1:${port}${own.cdp}`, { headers: { authorization: `Bearer ${key}` } })
    await browser.close()
    assert.equal((await api(key, 'GET', `/sessions/${own.id}/page`)).status, 200)
    assert.equal((await api(key, 'GET', '/blocked?host=example.com')).status, 200)
    assert.equal((await api(key, 'GET', '/drained')).status, 503)
  }
  for (const [i, result] of opened.entries()) assert.equal((await api(keys[i], 'DELETE', `/sessions/${result.body.id}`)).status, 200)
  const expired = await api(keys[0], 'POST', '/sessions', { site: { hosts: [] }, ttl_s: 0.01 })
  await new Promise(r => setTimeout(r, 1500))
  assert.equal((await api(keys[0], 'GET', `/sessions/${expired.body.id}/page`)).status, 410)
  assert.equal((await api(keys[1], 'GET', `/sessions/${expired.body.id}/log`)).status, 404)
  assert.equal((await api(keys[1], 'DELETE', `/sessions/${expired.body.id}`)).status, 404)
  assert.equal((await api(keys[0], 'DELETE', `/sessions/${expired.body.id}`)).status, 200)
})
