// Moves this checkout to the newest release CI made, then restarts the service: a systemd timer runs it (README), and never twice
// at once. A release is taken once every check on its commit has passed, and never past a prerelease, which a tag with a Manual:
// line makes for a release that needs a person first. A release that changed browser/ brings its image, pulled first however long
// that takes; otherwise the running image stays. Its packages are fetched first too, so a failure there, as without the network,
// changes nothing, and the next tick tries again. If the service doesn't answer after the move, code and image go back, and that
// release isn't tried again; if going back fails too, the service restarts as the checkout is, never left drained.
//   node scripts/update.ts      (BROWSER_KEY, and BROWSER_PORT if not 8797, from the service's environment file)
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'

const repo = 'spoj/rollforward-browser', image = 'ghcr.io/spoj/rollforward-browser'
const health = `http://127.0.0.1:${process.env.BROWSER_PORT ?? 8797}/sessions`, auth = { authorization: `Bearer ${process.env.BROWSER_KEY}` }
const app = join(dirname(fileURLToPath(import.meta.url)), '..'), state = join(homedir(), '.local', 'state', 'rollforward-browser-update.json')
const sh = (cmd: string, ...args: string[]) => execFileSync(cmd, args, { cwd: app, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] }).trim()
async function github(path: string) {
  const r = await fetch(`https://api.github.com/repos/${repo}${path}`, { headers: { accept: 'application/vnd.github+json' }, signal: AbortSignal.timeout(30_000) })
  if (!r.ok) throw new Error(`GitHub answered ${r.status} for ${path}`)
  return r.json()
}
const parts = (tag: string) => tag.slice(1).split('.').map(Number)
const later = (a: string, b: string) => { const x = parts(a), y = parts(b), i = x.findIndex((n, k) => n !== y[k]); return i >= 0 && x[i] > y[i] }

let current = ''
try {
  current = sh('git', 'describe', '--tags', '--exact-match', 'HEAD')
} catch {
  console.log(`the checkout is at ${sh('git', 'rev-parse', '--short', 'HEAD')}, on no release: updates wait until a person checks one out`)
  process.exit(1)
}
const bad: string[] = existsSync(state) ? JSON.parse(readFileSync(state, 'utf8')).bad : []
const releases = (await github('/releases?per_page=100')).filter((r: any) => !r.draft && /^v\d+\.\d+\.\d+$/.test(r.tag_name) && later(r.tag_name, current))
  .sort((a: any, b: any) => (later(a.tag_name, b.tag_name) ? 1 : -1))
const stop = releases.findIndex((r: any) => r.prerelease)
if (stop >= 0) console.log(`${releases[stop].tag_name} needs a person first: ${releases[stop].html_url}`)
const target: string | undefined = releases.slice(0, stop < 0 ? undefined : stop).map((r: any) => r.tag_name).filter((t: string) => !bad.includes(t)).at(-1)
if (!target) process.exit(0)
const checks = (await github(`/commits/${target}/check-runs?per_page=100`)).check_runs
if (!checks.length || checks.some((c: any) => c.status !== 'completed' || !['success', 'skipped'].includes(c.conclusion))) {
  console.log(`${target} waits for its checks to pass`)
  process.exit(0)
}

// The checkout at `to`, with what changed since `from` installed, `img` (if any) as the image the service runs, and the service restarted.
// The service drains first, on SIGUSR2, so the browsers open end on the release they opened on and their request logs reach
// rollforward: it opens no session, and says on /drained when every session has been collected, or 30 minutes have passed. One that
// restarted meanwhile, as v0.1.3 does when the signal kills it, or that doesn't answer within 35 minutes, is restarted all the same.
async function move(from: string, to: string, img?: string) {
  const pid = () => sh('systemctl', '--user', 'show', '--property=MainPID', '--value', 'rollforward-browser'), was = pid()
  if (was !== '0') {
    sh('systemctl', '--user', 'kill', '--kill-whom=main', '--signal=SIGUSR2', 'rollforward-browser')
    for (let i = 0; i < 420 && pid() === was && !(await fetch(new URL('/drained', health), { headers: auth }).then(r => r.ok, () => false)); i++) await sleep(5000)
  }
  sh('git', 'checkout', '-q', '--detach', to)
  if (sh('git', 'diff', '--name-only', from, to, '--', 'package-lock.json')) sh('npm', 'ci', '--omit=dev', '--no-audit', '--no-fund', '--offline')
  if (img) sh('podman', 'tag', img, 'rollforward-browser')
  sh('systemctl', '--user', 'restart', 'rollforward-browser')
}
async function answers() {
  for (let i = 0; i < 30; i++) {
    await sleep(2000)
    if (await fetch(health, { headers: auth }).then(r => r.ok, () => false)) return true
  }
  return false
}

console.log(`${current} -> ${target}`)
sh('git', 'fetch', '-q', '--tags', 'origin')
const fresh = sh('git', 'diff', '--name-only', current, target, '--', 'browser') ? `${image}:${target}` : undefined
// The target's packages, into npm's cache, from which the move installs them, and the move back what this one has.
if (sh('git', 'diff', '--name-only', current, target, '--', 'package-lock.json')) {
  const tmp = mkdtempSync(join(tmpdir(), 'rollforward-browser-update-'))
  try {
    for (const f of ['package.json', 'package-lock.json']) writeFileSync(join(tmp, f), sh('git', 'show', `${target}:${f}`))
    sh('npm', 'ci', '--omit=dev', '--no-audit', '--no-fund', '--prefix', tmp)
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
}
if (fresh) {
  console.log(`pulling ${fresh}`)
  sh('podman', 'pull', '-q', fresh)
  sh('podman', 'tag', 'rollforward-browser', 'rollforward-browser:previous')
}
try {
  await move(current, target, fresh)
  if (await answers()) {
    console.log(`on ${target}`)
    process.exit(0)
  }
  console.log(`${target} didn't answer ${health}`)
} catch (e) {
  console.log(`${target} failed: ${(e as Error).message}`)
}
// Recorded first, so a way back that fails too doesn't drain the service again at the next tick.
mkdirSync(dirname(state), { recursive: true })
writeFileSync(state, JSON.stringify({ bad: [...bad, target] }))
try {
  await move(target, current, fresh && 'rollforward-browser:previous')
  console.log(`back on ${current}; ${target} won't be tried again`)
} catch (e) {
  console.log(`going back to ${current} failed: ${(e as Error).message}; the service restarts as the checkout is, and ${target} won't be tried again`)
  sh('systemctl', '--user', 'restart', 'rollforward-browser')
}
process.exitCode = 1
