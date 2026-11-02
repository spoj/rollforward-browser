// Builds the golden Windows machine: an unattended install from the evaluation ISO (setup.ps1 installs the
// channel driver, Python and the helper), shut down once the helper answers, then a boot without the install
// discs to the signed-in desktop, saved with its memory.
// Usage: node windows/build.ts [path/to/windows.iso]   (needs virtio-win.iso in the windows data dir)
import fs from 'node:fs'
import { Vm, golden, windowsDir, run } from '../src/windows.ts'

const here = import.meta.dirname
const iso = process.argv[2] ?? `${windowsDir}/win11-eval.iso`
const python = 'python-3.14.10-amd64.exe'
const prov = `${windowsDir}/provision`
const settleS = Number(process.env.MACHINES_SETTLE_S ?? 180)

fs.rmSync(prov, { recursive: true, force: true })
fs.mkdirSync(`${prov}/wheels`, { recursive: true })
for (const f of ['autounattend.xml', 'setup.ps1', 'helper.py', 'requirements.txt']) fs.copyFileSync(`${here}/${f}`, `${prov}/${f}`)
if (!fs.existsSync(`${windowsDir}/${python}`)) await run('curl', ['-fsSL', '-o', `${windowsDir}/${python}`, `https://www.python.org/ftp/python/3.14.10/${python}`])
fs.copyFileSync(`${windowsDir}/${python}`, `${prov}/${python}`)
await run('pip', ['download', '--quiet', '--only-binary=:all:', '--platform', 'win_amd64', '--python-version', '3.14', '--implementation', 'cp', '-d', `${prov}/wheels`, '-r', `${here}/requirements.txt`])
await run('7z', ['e', '-bso0', `-o${prov}/vioserial`, `${windowsDir}/virtio-win.iso`, 'vioserial/w11/amd64/*'])
await run('genisoimage', ['-quiet', '-J', '-r', '-V', 'PROVISION', '-o', `${windowsDir}/provision.iso`, prov])

fs.rmSync(golden.disk, { force: true })
fs.rmSync(golden.state, { force: true })
await run('qemu-img', ['create', '-q', '-f', 'qcow2', golden.disk, '64G'])

const watch = (vm: Vm) => setInterval(() => vm.screenshot().then(png => fs.writeFileSync(`${windowsDir}/build.png`, png), () => {}), 30_000)

console.log('installing')
const install = new Vm(`${windowsDir}/build`, golden.disk, [
  '-drive', `file=${iso},media=cdrom,if=none,id=cd0,readonly=on`, '-device', 'ide-cd,drive=cd0,bus=ide.1,bootindex=2',
  '-drive', `file=${windowsDir}/provision.iso,media=cdrom,if=none,id=cd1,readonly=on`, '-device', 'ide-cd,drive=cd1,bus=ide.2',
])
await install.connect()
let timer = watch(install)
await install.ready(90 * 60_000)
console.log('helper up; shutting down to drop the install discs')
await install.request({ op: 'run', lang: 'powershell', script: 'shutdown /s /t 5', timeout_s: 60 })
await install.exited
clearInterval(timer)

console.log('booting to the desktop')
const boot = new Vm(`${windowsDir}/build`, golden.disk, [])
await boot.connect()
timer = watch(boot)
await boot.ready(30 * 60_000)
console.log(`helper up; settling ${settleS}s`)
await new Promise(r => setTimeout(r, settleS * 1000))
clearInterval(timer)
await boot.execute('stop')
await boot.migrate('migrate', golden.state)
boot.qemu.kill('SIGTERM')
await boot.exited
fs.chmodSync(golden.disk, 0o444)
fs.chmodSync(golden.state, 0o444)
console.log(`saved ${golden.disk} and ${golden.state}`)
