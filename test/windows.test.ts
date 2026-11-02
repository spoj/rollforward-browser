import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { once } from 'node:events'
import fs from 'node:fs'
import { golden, windowsDir } from '../src/windows.ts'

const port = 8796
const headers = { authorization: 'Bearer test-key' }
const api = async (method: string, path: string, body?: unknown) => {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers, body: typeof body === 'string' || body === undefined ? body : JSON.stringify(body) })
  return { status: res.status, body: res.headers.get('content-type') === 'application/json' ? await res.json() : Buffer.from(await res.arrayBuffer()) }
}
const skip = !fs.existsSync(golden.state) && 'no golden image: node windows/build.ts'
let service: ChildProcess

before(async () => {
  if (skip) return
  service = spawn('node', ['src/server.ts'], { env: { ...process.env, MACHINES_PORT: String(port), MACHINES_KEY: 'test-key' }, stdio: ['ignore', 'pipe', 'inherit'] })
  await once(service.stdout!, 'data')
})

after(() => service?.kill())

test('a windows machine runs scripts and moves files, with no network, and reverts on close', { skip }, async () => {
  const started = Date.now()
  const opened = await api('POST', '/sessions', { kind: 'windows' })
  assert.equal(opened.status, 201, JSON.stringify(opened.body))
  const { id } = opened.body
  console.log(`leased in ${Date.now() - started}ms`)
  const run = (lang: string, script: string, timeout_s = 60) => api('POST', `/sessions/${id}/run`, { lang, script, timeout_s }).then(r => r.body)

  const py = await run('python', 'import datetime, win32api\nprint(win32api.GetComputerName())\nprint(datetime.datetime.now(datetime.timezone.utc).isoformat())')
  assert.equal(py.exit, 0, py.stderr)
  const [name, now] = py.stdout.trim().split(/\r?\n/)
  assert.equal(name, 'MACHINE')
  assert.ok(Math.abs(Date.parse(now) - Date.now()) < 60_000, `guest clock ${now}`)

  const ps = await run('powershell', '(Get-NetAdapter).Count; (Get-Location).Path')
  assert.equal(ps.exit, 0, ps.stderr)
  assert.deepEqual(ps.stdout.trim().split(/\r?\n/), ['0', 'C:\\work'])

  assert.equal((await api('PUT', `/sessions/${id}/files/C:/work/in/note.txt`, 'héllo')).status, 204)
  const read = await run('python', 'print(open(r"C:\\work\\in\\note.txt", encoding="utf-8").read().upper())')
  assert.equal(read.stdout.trim(), 'HÉLLO')
  await run('powershell', 'Set-Content -Encoding ascii C:\\work\\out.txt done')
  assert.equal((await api('GET', `/sessions/${id}/files/C:/work/out.txt`)).body.toString().trim(), 'done')
  assert.equal((await api('GET', `/sessions/${id}/files/C:/work/nothing.txt`)).status, 404)

  const slow = await run('python', 'import time\ntime.sleep(30)', 2)
  assert.equal(slow.timed_out, true)

  const shot = await api('GET', `/sessions/${id}/screenshot`)
  assert.deepEqual([...shot.body.subarray(1, 4)], [...Buffer.from('PNG')])

  assert.deepEqual((await api('DELETE', `/sessions/${id}`)).body, {})
  assert.deepEqual(fs.readdirSync(`${windowsDir}/vms-${port}`).length, 1, 'only the next pooled clone is left')

  const again = await api('POST', '/sessions', { kind: 'windows' })
  const gone = await api('GET', `/sessions/${again.body.id}/files/C:/work/out.txt`)
  assert.equal(gone.status, 404, 'a new lease starts from the golden state')
  await api('DELETE', `/sessions/${again.body.id}`)
})
