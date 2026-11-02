# machines

Machines that an agent's code uses for a bounded task, then throws away. One client: the rollforward server, holding the service key.

- **browser**: a podman container per session with Chromium, driven over CDP (Playwright `connectOverCDP`). The container has no network (`--network none`), its own read-only image, and its home and profile in memory (`/tmp`, tmpfs). Its only way out is a proxy in this service, reached over a unix socket: the proxy ends TLS itself (the browser accepts exactly this service's key), so it sees every request whole, keeps to the site's hosts, blocks writes, and logs each request.
- **windows**: not yet.

## Run

    podman build -t machines-browser browser
    npm install
    MACHINES_KEY=... MACHINES_PORT=8797 node src/server.ts

It listens on 127.0.0.1 only (default port 8797; never 8790). Leftover containers and runtime files of an earlier run on the same port are removed at start. `NODE_EXTRA_CA_CERTS` adds CAs the proxy trusts upstream (an ERP with an internal CA). Tests: `npm test` (needs the image).

## API

Every request carries `Authorization: Bearer $MACHINES_KEY`. Errors are `{error}` with a status: 400, 401, 404 (no such session, route or file), 410 (the session's ttl ran out), 500.

`POST /sessions` `{kind: "browser", site: {hosts, start_url?, reads_that_post?}, state?, ttl_s?}` → 201 `{id, cdp, view}`

- `hosts`: names the browser may reach, exact (`erp.example`) or `*.example` for any name under it. Anything else gets a 403 page.
- Internal addresses (private, loopback, link-local, CGNAT, unique-local) are reachable only through a name listed exactly: a name matched by a wildcard that resolves only to internal addresses gets a 502. IP literals must be listed exactly.
- Writes: requests other than GET, HEAD and OPTIONS get a 403, unless their URL matches a `reads_that_post` pattern (`*` matches anything, matched against the whole URL, e.g. `https://erp.example/jde/*.mafService*`) or a person is driving the live view.
- `state`: a Playwright storageState (`{cookies, origins: [{origin, localStorage}]}`), loaded before the call returns. It lives only in the service's memory and the container's tmpfs.
- `start_url`: the first tab goes there before the call returns (until the response arrives, not the load).
- `ttl_s` (default 3600): then the session closes on its own; its result (below) waits for `DELETE`.
- `cdp` and `view` are paths on this service.

`GET /sessions/:id/cdp` — websocket: CDP of the whole browser, for `chromium.connectOverCDP(url, {headers})`. Use `browser.contexts()[0]` (the saved login is there).

`GET /sessions/:id/view` — the live view page: the browser's tabs, screencast, an address bar. It watches until the person presses Take control; then their mouse and keyboard go to the page and writes are allowed while they hold control. The page connects to the websockets `view/watch` and `view/drive` relative to its own URL (CDP like `cdp`; a `drive` connection is what counts as a person driving), so a proxy in front must pass those through, adding the key.

`GET /sessions/:id/log` → `[{t, method, url, status, blocked?, error?, live?}]`, every request the browser made, in order: `blocked` says why the proxy refused it (403), `error` why upstream failed (502), `live` that a person was driving. Works after the ttl too.

`GET /sessions/:id/screenshot` → PNG of the newest tab.

`GET|PUT /sessions/:id/files/<path>` — read or write a file in the container by absolute path (`PUT` makes the directories). Downloads land where the agent's Playwright tells Chromium; `await download.path()` gives that path (`/tmp/playwright-artifacts-…/<guid>`), so fetch `GET /sessions/:id/files/tmp/playwright-artifacts-…/<guid>`. (`download.saveAs()` can't work: the file is in the container, not where the agent's Playwright runs.)

`DELETE /sessions/:id` → `{state, log}`: the refreshed login (null if the browser was gone) and the whole request log. Then the container, its memory and the session's sockets are gone. A second `DELETE` is a 404.

`GET /sessions` → `[{id, kind, expires, closed}]`.

## Notes for clients

- Playwright's `page.request` / `context.request` run in the agent's own process, not in the browser: they would leave from the agent's sandbox, not through this proxy. To use the page's cookies, fetch inside the page: `page.evaluate(u => fetch(u).then(r => r.text()), url)`.
- The write rule is a firm default, not a wall: the agent's code drives a real browser.
- Run the service as its own user: CDP is close to code execution in the container, and the container's user is the service's user (`--userns keep-id`).
