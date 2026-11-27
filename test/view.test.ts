import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import vm from 'node:vm'

const html = fs.readFileSync(new URL('../src/view.html', import.meta.url), 'utf8')
const script = html.match(/<script type="module">([\s\S]*)<\/script>/)![1]

function boot(search = '') {
  const sent: any[] = []
  let ws: any
  const buttons: any[] = []
  const elements: Record<string, any> = {
    img: { src: '', getBoundingClientRect: () => ({ left: 0, top: 0, width: 100, height: 100 }) },
    url: { value: '', disabled: false },
    tabs: { replaceChildren: (...els: any[]) => { buttons.length = 0; buttons.push(...els) } },
    drive: { textContent: '', hidden: false },
    kb: { value: '', focus() {}, blur() {} },
  }
  class FakeWS {
    url: string
    onopen?: () => void
    onclose?: () => void
    onmessage?: (e: { data: string }) => void
    constructor(url: string) { this.url = url; ws = this }
    send(raw: string) { sent.push(JSON.parse(raw)) }
    close() { this.onclose?.() }
  }
  const ctx = vm.createContext({
    document: {
      title: '',
      activeElement: null,
      body: { classList: { toggle() {} } },
      getElementById: (id: string) => elements[id],
      createElement: () => ({ textContent: '', title: '', className: '', onclick: null }),
    },
    location: { href: `http://localhost/sessions/s1/view${search}`, search },
    URL, URLSearchParams, WebSocket: FakeWS,
  })
  vm.runInContext(script, ctx)
  ws.onopen()
  const recv = (m: any) => ws.onmessage({ data: JSON.stringify(m) })
  const ackAttach = (sessionId: string) => {
    const req = sent.findLast(m => m.method === 'Target.attachToTarget')
    recv({ id: req.id, result: { sessionId } })
  }
  const flush = () => new Promise(r => setImmediate(r))
  return { sent, buttons, recv, ackAttach, flush }
}

test('watching auto-follows new tabs, respects manual pin, and falls back to newest tab on close', async () => {
  const { sent, buttons, recv, ackAttach, flush } = boot('?watch')
  recv({ method: 'Target.targetCreated', params: { targetInfo: { targetId: 't1', type: 'page', title: 'Menu', url: 'https://e1/menu' } } })
  assert.equal(sent.at(-1).params.targetId, 't1')
  ackAttach('s1'); await flush()

  // New tab created by e1_query.py -> auto-follows while watching
  recv({ method: 'Target.targetCreated', params: { targetInfo: { targetId: 't2', type: 'page', title: 'Query', url: 'https://e1/query' } } })
  assert.equal(sent.at(-1).method, 'Target.attachToTarget')
  assert.equal(sent.at(-1).params.targetId, 't2')
  ackAttach('s2'); await flush()
  assert.equal(sent.at(-1).method, 'Page.startScreencast')
  assert.equal(sent.at(-1).sessionId, 's2')

  // Watcher manually clicks older tab t1 -> pins to t1, ignores t3 creation
  buttons[0].onclick()
  assert.equal(sent.at(-1).params.targetId, 't1')
  ackAttach('s3'); await flush()
  const countBefore = sent.length
  recv({ method: 'Target.targetCreated', params: { targetInfo: { targetId: 't3', type: 'page', title: 'Popup', url: 'https://e1/p' } } })
  assert.equal(sent.length, countBefore, 'pinned watcher is not yanked to new tab')

  // Clicking newest tab t3 unpins; destroying t3 falls back to newest remaining (t2)
  buttons[2].onclick()
  ackAttach('s4'); await flush()
  recv({ method: 'Target.targetDestroyed', params: { targetId: 't3' } })
  assert.equal(sent.at(-1).method, 'Target.attachToTarget')
  assert.equal(sent.at(-1).params.targetId, 't2')
})

test('driving mode does not auto-switch when another tab opens', async () => {
  const { sent, recv, ackAttach, flush } = boot('?drive')
  recv({ method: 'Target.targetCreated', params: { targetInfo: { targetId: 't1', type: 'page', title: 'Login', url: 'https://e1/login' } } })
  ackAttach('s1'); await flush()
  const countBefore = sent.length
  recv({ method: 'Target.targetCreated', params: { targetInfo: { targetId: 't2', type: 'page', title: 'Popup', url: 'https://e1/popup' } } })
  assert.equal(sent.length, countBefore, 'driver stays on current tab')
})

test('out-of-order attachToTarget detaches stale session instead of hijacking current tab', async () => {
  const { sent, recv, flush } = boot('?watch')
  recv({ method: 'Target.targetCreated', params: { targetInfo: { targetId: 't1', type: 'page', title: 'T1', url: 'https://e1/1' } } })
  const attach1 = sent.findLast(m => m.method === 'Target.attachToTarget')
  recv({ method: 'Target.targetCreated', params: { targetInfo: { targetId: 't2', type: 'page', title: 'T2', url: 'https://e1/2' } } })
  const attach2 = sent.findLast(m => m.method === 'Target.attachToTarget')
  // Resolve attach2 first, then stale attach1
  recv({ id: attach2.id, result: { sessionId: 's2' } }); await flush()
  recv({ id: attach1.id, result: { sessionId: 's1' } }); await flush()
  assert.ok(sent.some(m => m.method === 'Target.detachFromTarget' && m.params.sessionId === 's1'), 'stale session detached')
  assert.ok(!sent.some(m => m.method === 'Page.startScreencast' && m.sessionId === 's1'), 'stale session never starts screencast')
})

test('failed attach on multiple transient popups cascades back to surviving tab without freezing', async () => {
  const { sent, recv, ackAttach, flush } = boot('?watch')
  recv({ method: 'Target.targetCreated', params: { targetInfo: { targetId: 't1', type: 'page', title: 'Main', url: 'https://e1/main' } } })
  ackAttach('s1'); await flush()
  recv({ method: 'Target.targetCreated', params: { targetInfo: { targetId: 't2', type: 'page', title: 'Pop1', url: 'https://e1/pop1' } } })
  recv({ method: 'Target.targetCreated', params: { targetInfo: { targetId: 't3', type: 'page', title: 'Pop2', url: 'https://e1/pop2' } } })
  const fail3 = sent.findLast(m => m.method === 'Target.attachToTarget' && m.params.targetId === 't3')
  recv({ id: fail3.id, error: { code: -32000, message: 'No target with given id found' } }); await flush()
  assert.equal(sent.at(-1).method, 'Target.attachToTarget')
  assert.equal(sent.at(-1).params.targetId, 't2', 'tries next newest tab t2')
  const fail2 = sent.at(-1)
  recv({ id: fail2.id, error: { code: -32000, message: 'No target with given id found' } }); await flush()
  assert.equal(sent.at(-1).method, 'Target.attachToTarget')
  assert.equal(sent.at(-1).params.targetId, 't1', 'cascades back to surviving tab t1')
})

test('Live View HUD polls /view/activity with textContent-only DOM, suppresses on ?drive and live control, and stops permanently on 404', async () => {
  assert.ok(!script.includes('innerHTML') && !script.includes('insertAdjacentHTML'), 'view.html script never uses innerHTML')

  const makeHudBoot = (search: string, responses: Array<{ status: number; body?: any }>) => {
    const fetched: string[] = []
    const createdRows: any[] = []
    let timerCb: (() => void) | null = null
    let timerCleared = false
    const hudClasses = new Set<string>()
    const elements: Record<string, any> = {
      img: { src: '', getBoundingClientRect: () => ({ left: 0, top: 0, width: 100, height: 100 }) },
      url: { value: '', disabled: false },
      tabs: { replaceChildren() {} },
      drive: { textContent: '', hidden: false, onclick: null },
      kb: { value: '', focus() {}, blur() {} },
      hud: { hidden: true, classList: { toggle: (c: string, on: boolean) => on ? hudClasses.add(c) : hudClasses.delete(c) } },
      'hud-bar': { onclick: null },
      'hud-summary': { textContent: '' },
      'hud-counts': { textContent: '' },
      'hud-toggle': { textContent: 'Expand' },
      'hud-list': { replaceChildren: (...rows: any[]) => { createdRows.length = 0; createdRows.push(...rows) } },
    }
    class FakeWS {
      onopen?: () => void
      onclose?: () => void
      onmessage?: (e: { data: string }) => void
      send() {}
      close() {}
    }
    const ctx = vm.createContext({
      document: {
        title: '',
        activeElement: null,
        body: { classList: { toggle() {} } },
        getElementById: (id: string) => elements[id],
        createElement: () => ({ textContent: '', title: '', className: '', onclick: null }),
      },
      location: { href: `http://localhost/sessions/s1/view${search}`, search },
      URL, URLSearchParams, WebSocket: FakeWS,
      fetch: async (u: string) => {
        fetched.push(u)
        const next = responses.shift() ?? { status: 200, body: { live: false, nextCursor: 1, writeCount: 0, blockedCount: 0, dropped: 0, events: [] } }
        return { status: next.status, ok: next.status >= 200 && next.status < 300, json: async () => next.body }
      },
      setTimeout: (fn: () => void) => { timerCb = fn; return 1 },
      clearTimeout: () => { timerCleared = true; timerCb = null },
    })
    vm.runInContext(script, ctx)
    const flush = () => new Promise(r => setImmediate(r))
    return { elements, fetched, createdRows, hudClasses, flush, tick: () => { const f = timerCb; timerCb = null; f?.() }, wasCleared: () => timerCleared }
  }

  // 1. ?drive suppresses HUD completely (zero fetches)
  const driveHud = makeHudBoot('?drive', [])
  await driveHud.flush()
  assert.equal(driveHud.fetched.length, 0)
  assert.equal(driveHud.elements.hud.hidden, true)

  // 2. Watching polls /view/activity, renders textContent-only rows, expands/collapses, hides while driving
  const watchHud = makeHudBoot('?watch', [
    { status: 200, body: { live: false, nextCursor: 2, writeCount: 1, blockedCount: 0, dropped: 0, events: [{ n: 2, t: '2026-11-27T12:00:00Z', kind: 'http', method: 'POST', status: 200, isWrite: true, detail: 'erp.example/api/<script>' }] } },
  ])
  await watchHud.flush()
  await watchHud.flush()
  assert.equal(watchHud.fetched.length, 1)
  assert.match(watchHud.fetched[0], /\/sessions\/s1\/view\/activity\?after=0$/)
  assert.equal(watchHud.elements.hud.hidden, false)
  assert.equal(watchHud.createdRows.length, 1)
  assert.match(watchHud.createdRows[0].textContent, /POST 200 erp\.example\/api\/<script>/)
  watchHud.elements['hud-bar'].onclick()
  assert.equal(watchHud.hudClasses.has('open'), true)
  assert.equal(watchHud.elements['hud-toggle'].textContent, 'Collapse')
  // Taking control hides HUD and clears timer
  watchHud.elements.drive.onclick()
  assert.equal(watchHud.elements.hud.hidden, true)
  assert.equal(watchHud.wasCleared(), true)

  // 3. 404 stops HUD permanently
  const errHud = makeHudBoot('', [{ status: 404 }])
  await errHud.flush()
  await errHud.flush()
  assert.equal(errHud.fetched.length, 1)
  assert.equal(errHud.elements.hud.hidden, true)
  errHud.tick()
  await errHud.flush()
  assert.equal(errHud.fetched.length, 1, 'never polls again after 404')
})
