import { spawn, type ChildProcess } from 'node:child_process'
import { once } from 'node:events'
import net from 'node:net'
import fs from 'node:fs'
import os from 'node:os'
import crypto from 'node:crypto'

export const windowsDir = `${process.env.MACHINES_DATA ?? `${os.homedir()}/.local/share/machines`}/windows`
export const golden = { disk: `${windowsDir}/golden.qcow2`, state: `${windowsDir}/golden.state` }

// The machine every clone gets, exactly as the golden state was saved from: a restore needs the same devices.
// No network device at all: the host speaks to the guest helper over the virtio-serial port only.
export const qemuArgs = (disk: string, dir: string) => [
  '-nodefaults', '-run-with', 'exit-with-parent=on', '-machine', 'pc-q35-11.1,accel=kvm', '-smp', '4', '-m', '4096',
  '-cpu', 'host,hv_relaxed,hv_vapic,hv_spinlocks=0x1fff,hv_time,hv_vpindex,hv_synic,hv_stimer,hv_frequencies,hv_reset,hv_runtime',
  '-rtc', 'base=utc', '-vga', 'std', '-display', 'none',
  '-drive', `file=${disk},if=none,id=disk,format=qcow2,discard=unmap`, '-device', 'ide-hd,drive=disk,bus=ide.0,bootindex=1',
  '-device', 'virtio-serial-pci', '-chardev', `socket,id=channel,path=${dir}/channel.sock,server=on,wait=off`,
  '-device', 'virtserialport,chardev=channel,name=org.machines.0',
  '-qmp', `unix:${dir}/qmp.sock,server=on,wait=off`,
]

const connect = async (path: string) => {
  for (let i = 0; ; i++) {
    const s = net.connect(path)
    try {
      await once(s, 'connect')
      return s
    } catch (e) {
      if (i === 100) throw e
      await new Promise(r => setTimeout(r, 100))
    }
  }
}

// Newline-delimited JSON with ids, as both QMP and the guest helper speak it.
class Lines {
  socket: net.Socket
  pending = new Map<number, { resolve: (v: any) => void, reject: (e: Error) => void }>()
  next = 1
  constructor(socket: net.Socket, onMessage: (m: any) => void) {
    this.socket = socket
    let buf = ''
    socket.setEncoding('utf8')
    socket.on('data', (chunk: string) => {
      buf += chunk
      for (let i; (i = buf.indexOf('\n')) >= 0; buf = buf.slice(i + 1)) onMessage(JSON.parse(buf.slice(0, i)))
    })
    socket.on('error', () => {})
    socket.on('close', () => this.pending.forEach(p => p.reject(new Error('machine closed'))))
  }
  send(msg: object) {
    const id = this.next++
    this.socket.write(JSON.stringify({ ...msg, id }) + '\n')
    return new Promise<any>((resolve, reject) => this.pending.set(id, { resolve, reject }))
  }
  settle(id: number, error: string | undefined, value: any) {
    const p = this.pending.get(id)
    this.pending.delete(id)
    error ? p?.reject(new Error(error)) : p?.resolve(value)
  }
}

export class Vm {
  qemu: ChildProcess
  dir: string
  disk: string
  qmp!: Lines
  channel!: Lines
  exited: Promise<unknown>

  constructor(dir: string, disk: string, extra: string[]) {
    this.dir = dir
    this.disk = disk
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
    this.qemu = spawn('qemu-system-x86_64', [...qemuArgs(disk, dir), ...extra], { stdio: ['ignore', 'inherit', 'inherit'] })
    this.exited = once(this.qemu, 'exit')
  }

  async connect() {
    const greeted = Promise.withResolvers<void>()
    this.qmp = new Lines(await connect(`${this.dir}/qmp.sock`), m => m.QMP ? greeted.resolve() : 'id' in m && this.qmp.settle(m.id, m.error?.desc, m.return))
    await greeted.promise
    await this.execute('qmp_capabilities')
    this.channel = new Lines(await connect(`${this.dir}/channel.sock`), m => this.channel.settle(m.id, m.error, m))
  }

  execute(command: string, args?: object) {
    return this.qmp.send({ execute: command, ...(args ? { arguments: args } : {}) })
  }

  request(msg: object) {
    return this.channel.send(msg)
  }

  // Answers once the helper runs; until then the ping waits in the port.
  async ready(timeoutMs: number) {
    const timeout = AbortSignal.timeout(timeoutMs)
    for (;;) {
      const ok = await Promise.race([this.request({ op: 'ping' }).then(() => true), new Promise(r => setTimeout(r, 5000, false))])
      if (ok) return
      timeout.throwIfAborted()
    }
  }

  async screenshot() {
    const file = `${this.dir}/screen.png`
    await this.execute('screendump', { filename: file, format: 'png' })
    const png = fs.readFileSync(file)
    fs.rmSync(file)
    return png
  }

  async migrate(command: 'migrate' | 'migrate-incoming', file: string) {
    await this.execute(command, { uri: `file:${file}` })
    for (;;) {
      const { status } = command === 'migrate' ? await this.execute('query-migrate') : await this.execute('query-status')
      if (status === 'completed' || status === 'paused') return
      if (status === 'failed') throw new Error(`${command} failed`)
      await new Promise(r => setTimeout(r, 100))
    }
  }

  async kill() {
    this.qemu.kill('SIGKILL')
    await this.exited
    fs.rmSync(this.dir, { recursive: true, force: true })
  }
}

// A clone: a throwaway overlay on the golden disk, loaded with the golden memory state and left paused.
async function restore(dir: string) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  const disk = `${dir}/disk.qcow2`
  await run('qemu-img', ['create', '-q', '-f', 'qcow2', '-b', golden.disk, '-F', 'qcow2', disk])
  const vm = new Vm(dir, disk, ['-incoming', 'defer', '-S'])
  try {
    await vm.connect()
    await vm.migrate('migrate-incoming', golden.state)
    return vm
  } catch (e) {
    await vm.kill()
    throw e
  }
}

// Clones wait paused in the pool; a lease resumes one, so it is signed in and idle within seconds.
const poolSize = Number(process.env.MACHINES_WINDOWS_POOL ?? 1)
const max = Number(process.env.MACHINES_WINDOWS_MAX ?? 3)
const ready: Vm[] = []
let vmsDir = ''
let running = 0
let warming = 0

export function startPool(dir: string) {
  vmsDir = dir
  fs.rmSync(dir, { recursive: true, force: true })
  refill()
}

function refill() {
  while (fs.existsSync(golden.state) && warming + ready.length < poolSize && running < max) {
    running++
    warming++
    restore(`${vmsDir}/${crypto.randomUUID()}`).then(vm => {
      warming--
      ready.push(vm)
    }, e => {
      warming--
      running--
      console.error('windows clone failed:', e)
    })
  }
}

async function lease() {
  let vm = ready.shift()
  if (!vm) {
    if (running >= max) throw Object.assign(new Error('no windows machine free'), { status: 503 })
    running++
    vm = await restore(`${vmsDir}/${crypto.randomUUID()}`).catch(e => { running--; throw e })
  }
  refill()
  try {
    await vm.execute('cont')
    await vm.ready(30_000)
    await vm.request({ op: 'time', utc: new Date().toISOString() })
    return vm
  } catch (e) {
    await release(vm)
    throw e
  }
}

async function release(vm: Vm) {
  await vm.kill()
  running--
  refill()
}

const inMachine = (path: string) => path.replace(/^\/(?=[A-Za-z]:)/, '')

export class WindowsSession {
  kind = 'windows' as const
  log: never[] = []
  id: string
  vm?: Vm

  constructor(id: string) {
    this.id = id
  }

  async start() {
    this.vm = await lease()
  }

  async run(lang: string, script: string, timeout_s: number) {
    const { id, ...result } = await this.vm!.request({ op: 'run', lang, script, timeout_s })
    return result
  }

  async readFile(path: string) {
    return Buffer.from((await this.vm!.request({ op: 'get', path: inMachine(path) })).data, 'base64')
  }

  async writeFile(path: string, data: Buffer) {
    await this.vm!.request({ op: 'put', path: inMachine(path), data: data.toString('base64') })
  }

  screenshot() {
    return this.vm!.screenshot()
  }

  async close() {
    if (this.vm) await release(this.vm)
    return {}
  }
}

export async function run(cmd: string, args: string[]) {
  const p = spawn(cmd, args, { stdio: ['ignore', 'inherit', 'inherit'] })
  const [code] = await once(p, 'exit')
  if (code) throw new Error(`${cmd} exited ${code}`)
}
