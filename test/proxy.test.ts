import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { once } from 'node:events'
import fs from 'node:fs'
import http from 'node:http'
import net from 'node:net'
import os from 'node:os'
import { startProxy, type Entry } from '../src/proxy.ts'

test('a via proxy that takes the connection and never answers CONNECT gives the request a 502 after 30s', async t => {
  const pem = execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=test', '-keyout', '-', '-out', '-'], { stdio: ['ignore', 'pipe', 'ignore'] }).toString()
  const key = { key: pem.slice(0, pem.indexOf('-----BEGIN CERTIFICATE')), cert: pem.slice(pem.indexOf('-----BEGIN CERTIFICATE')) }
  const silent = http.createServer().on('connect', () => {}).listen(0, '127.0.0.1')
  await once(silent, 'listening')
  const dir = fs.mkdtempSync(`${os.tmpdir()}/rollforward-browser-proxy-test-`), log: Entry[] = []
  const proxy = startProxy(`${dir}/proxy.sock`, { hosts: ['t.example'], via: { url: `http://127.0.0.1:${(silent.address() as net.AddressInfo).port}`, token: 'via-secret', hosts: ['t.example'] } }, key, () => false, log)
  t.after(() => {
    proxy.close()
    silent.closeAllConnections()
    silent.close()
    fs.rmSync(dir, { recursive: true })
  })
  await once(proxy, 'listening')
  const socket = net.connect(`${dir}/proxy.sock`)
  socket.write('GET http://t.example/ HTTP/1.1\r\nhost: t.example\r\nconnection: close\r\n\r\n')
  assert.match(Buffer.concat(await socket.toArray()).toString(), /^HTTP\/1.1 502[^]*no answer in 30s/)
  assert.deepEqual(log.map(e => [e.status, e.error]), [[502, 'upstream proxy CONNECT: no answer in 30s']])
})
