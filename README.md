# machines

Machines that an agent's code uses for a bounded task, then throws away. One client: the rollforward server, holding the service key.

- **browser**: a podman container per session with Chromium, driven over CDP (Playwright `connectOverCDP`). The container has no network (`--network none`), its own read-only image, and its home and profile in memory (`/tmp`, tmpfs). Its only way out is a proxy in this service, reached over a unix socket: the proxy ends TLS itself (the browser accepts exactly this service's key), so it sees every request whole, keeps to the site's hosts, blocks writes, and logs each request.
- **windows**: a Windows VM (KVM, QEMU driven directly), leased for a bounded task and then thrown away. Clones of one golden machine, saved signed in and idle with its memory, wait paused in a pool; a lease resumes one (seconds) and sets its clock; closing kills it and discards its disk overlay, so the next lease starts from the golden state again. No network device at all: the host talks to a helper in the signed-in session over a virtio-serial port (scripts, files), and takes screenshots itself (QMP `screendump`, which works when Windows hangs on a dialog).

## Run

    podman build -t machines-browser browser
    npm install
    MACHINES_KEY=... node src/server.ts

It listens on 127.0.0.1 only, port `MACHINES_PORT` (default 8797; never 8790). Leftovers of an earlier run on the same port (containers, runtime files, VM overlays) are removed at start; VMs die with the service. `NODE_EXTRA_CA_CERTS` adds CAs the proxy trusts upstream (an ERP with an internal CA). Run it as its own user: CDP is close to code execution in the container, whose user is the service's user (`--userns keep-id`).

Windows needs a golden machine first: about 40 minutes, unattended, from the Windows 11 evaluation ISO and virtio-win.iso in `~/.local/share/machines/windows/` (or `$MACHINES_DATA/windows/`):

    node windows/build.ts [windows.iso]

It writes `golden.qcow2` and `golden.state` there; clones' overlays live in `vms-<port>/`. `MACHINES_WINDOWS_POOL` (default 1) clones wait paused; at most `MACHINES_WINDOWS_MAX` (default 3) run at once. The machine: 4 vCPUs, 4 GB, Windows 11 Enterprise evaluation (90 days), local administrator `machines` signed in automatically (its password only matters inside the offline VM), UAC off, Python 3.14 with pywin32 (`windows/requirements.txt`), working directory `C:\work`. No Office yet.

Tests: `npm test` (the browser image; the windows test runs once the golden machine exists).

## API

Every request carries `Authorization: Bearer $MACHINES_KEY`. Errors are `{error}` with a status: 400, 401, 404 (no such session, route or file), 410 (the session's ttl ran out), 503 (no windows machine free), 500.

`POST /sessions` `{kind, ..., ttl_s?}` → 201 `{id, ...}`. After `ttl_s` (default 3600) the session closes on its own; its result waits for `DELETE`.

`DELETE /sessions/:id` → the session's result; then the machine is gone. A second `DELETE` is a 404.

`GET /sessions/:id/screenshot` → PNG.

`GET|PUT /sessions/:id/files/<path>` — read or write a file in the machine by absolute path (`PUT` makes the directories): `/files/tmp/x` in a browser's container, `/files/C:/work/x.xlsx` in windows.

`GET /sessions` → `[{id, kind, expires, closed}]`.

### browser

`POST /sessions` `{kind: "browser", site: {hosts, start_url?, reads_that_post?}, state?}` → `{id, cdp, view}` (paths on this service)

- `hosts`: names the browser may reach, exact (`erp.example`) or `*.example` for any name under it. Anything else gets a 403 page.
- Internal addresses (private, loopback, link-local, CGNAT, unique-local) are reachable only through a name listed exactly: a name matched by a wildcard that resolves only to internal addresses gets a 502. IP literals must be listed exactly.
- Writes: requests other than GET, HEAD and OPTIONS get a 403, unless their URL matches a `reads_that_post` pattern (`*` matches anything, matched against the whole URL, e.g. `https://erp.example/jde/*.mafService*`) or a person is driving the live view.
- `state`: a Playwright storageState (`{cookies, origins: [{origin, localStorage}]}`), loaded before the call returns. It lives only in the service's memory and the container's tmpfs.
- `start_url`: the first tab goes there before the call returns (until the response arrives, not the load).

`GET /sessions/:id/cdp` — websocket: CDP of the whole browser, for `chromium.connectOverCDP(url, {headers})`. Use `browser.contexts()[0]` (the saved login is there).

`GET /sessions/:id/view` — the live view page: the browser's tabs, screencast, an address bar. It watches until the person presses Take control; then their mouse and keyboard go to the page and writes are allowed while they hold control. The page connects to the websockets `view/watch` and `view/drive` relative to its own URL (CDP like `cdp`; a `drive` connection is what counts as a person driving), so a proxy in front must pass those through, adding the key.

`GET /sessions/:id/log` → `[{t, method, url, status, blocked?, error?, live?}]`, every request the browser made, in order: `blocked` says why the proxy refused it (403), `error` why upstream failed (502), `live` that a person was driving. Works after the ttl too.

The screenshot is of the newest tab. Downloads land where the agent's Playwright tells Chromium: `await download.path()` gives that path in the container (`/tmp/playwright-artifacts-…/<guid>`), so fetch `GET /sessions/:id/files/tmp/playwright-artifacts-…/<guid>`; `download.saveAs()` can't work, as the file isn't where the agent's Playwright runs.

`DELETE` → `{state, log}`: the refreshed login (null if the browser was gone) and the whole request log.

### windows

`POST /sessions` `{kind: "windows"}` → `{id}` once a clone is resumed, signed in and its clock set.

`POST /sessions/:id/run` `{lang: "python"|"powershell", script, timeout_s}` → `{exit, stdout, stderr, timed_out?}`: the script runs in the signed-in session, in `C:\work`; past `timeout_s` its process tree is killed and `exit` is null. One request at a time per machine: others wait their turn.

`DELETE` → `{}`.

## Notes for clients

- Playwright's `page.request` / `context.request` run in the agent's own process, not in the browser: they would leave from the agent's sandbox, not through this proxy. To use the page's cookies, fetch inside the page: `page.evaluate(u => fetch(u).then(r => r.text()), url)`.
- The write rule is a firm default, not a wall: the agent's code drives a real browser.

## Open items

- **Licence:** the evaluation never activates, as the VM has no network (`LicenseStatus` 5, "Windows License is expired" on the desktop, from both the 25H2 and the 26H2 evaluation ISOs), and an unactivated evaluation may shut down hourly, inside a 2-hour lease. Real use needs a licence from IT that activates offline or through a KMS host the host relays to.
- **PowerShell** stalled at startup in the specialize pass of setup (hence `setup.cmd`); in a signed-in clone it runs.
- **Chromium** still posts twice per session to `update.googleapis.com`; the proxy blocks both (log noise only).
