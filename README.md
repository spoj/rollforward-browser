# rollforward-browser

Browsers that an agent's code uses for a bounded task on one website, then throws away. One client: the [rollforward](https://github.com/spoj/rollforward) server, holding the service key.

Each session is a podman container with Chromium, driven over CDP (Playwright `connectOverCDP`). The container has no network (`--network none`), its own read-only image, and its home and profile in memory (`/tmp`, tmpfs). Its only way out is a proxy in this service, reached over a unix socket: the proxy ends TLS itself (the browser accepts exactly this service's key), so it sees every request whole, keeps to the site's hosts and logs each request.

## Run

Needs Node 26 and rootless podman (tested with 6.1).

    podman build -t rollforward-browser browser
    npm install
    BROWSER_KEY=$(openssl rand -hex 32) node src/server.ts

Where the image can't be built, as on a host that can't reach Debian's mirrors, pull the one each tag publishes and give it the name the service runs: `podman pull ghcr.io/spoj/rollforward-browser:TAG && podman tag ghcr.io/spoj/rollforward-browser:TAG rollforward-browser`.

It listens on `BROWSER_HOST` (default 127.0.0.1), port `BROWSER_PORT` (default 8797). The key is the one secret its client holds: rollforward's `RF_BROWSER_KEY`, with `RF_BROWSER_URL` its address. `curl -H "authorization: Bearer $BROWSER_KEY" http://127.0.0.1:8797/sessions` answers `[]` when it's up. Leftovers of an earlier run on the same port (containers, runtime files) are removed at start. `NODE_EXTRA_CA_CERTS` adds CAs the proxy trusts upstream (an ERP with an internal CA).

Run it as a user of its own, next to rollforward's: CDP is close to code execution in the container, whose user is the service's user (`--userns keep-id`). As a systemd user service of that user, with lingering on (`loginctl enable-linger USER`):

    # ~/.config/systemd/user/rollforward-browser.service
    [Service]
    WorkingDirectory=%h/rollforward-browser
    EnvironmentFile=%h/.config/rollforward-browser.env
    ExecStart=/usr/bin/node src/server.ts
    Restart=on-failure

    [Install]
    WantedBy=default.target

with `BROWSER_KEY=...` in `~/.config/rollforward-browser.env`, then `systemctl --user enable --now rollforward-browser`. `ExecStart` names Node 26 where it is, such as `/opt/node-v26/bin/node` beside an older system node.

On a host of its own, such as a VM next to rollforward's:

- **Listen on the private interface:** `BROWSER_HOST`, an IPv4 address of this host, such as `10.0.0.5`.
- **Let only the rollforward host in:** a firewall rule allowing its address to `BROWSER_PORT`, and nothing else.
- **Encrypt the link:** CDP and the live view carry signed-in sessions, and the key goes with every request. Either listen on a private link, WireGuard or Tailscale, and give rollforward its `http://` address there; or keep `BROWSER_HOST` at 127.0.0.1 behind a reverse proxy that ends TLS and passes websockets, such as Caddy, and give rollforward its `https://` address (with `NODE_EXTRA_CA_CERTS` on the rollforward host for a private CA).
- **The sites are reached from here:** browsers' requests leave from this host, so it needs the routes to the sites (the ERP, the portals) and, for an internal CA, `NODE_EXTRA_CA_CERTS`; the rollforward host doesn't.
- **Sizing:** a browser container is capped at 2 GB, about 0.2 GB idle and more on heavy sites.

Tests: `npm test` (needs the image).

## API

Every request carries `Authorization: Bearer $BROWSER_KEY`. Errors are `{error}` with a status: 401, 404 (no such session, route or file), 410 (the session's ttl ran out), 500.

`POST /sessions` `{site: {hosts, start_url?}, state?, ttl_s?}` → 201 `{id, cdp, view}` (paths on this service). After `ttl_s` (default 3600) the session closes on its own; its result waits for `DELETE`.

- `hosts`: names the browser may reach, exact (`erp.example`) or `*.example` for any name under it. Anything else gets a 403 page.
- Internal addresses (private, loopback, link-local, CGNAT, unique-local) are reachable only through a name listed exactly: a name matched by a wildcard that resolves only to internal addresses gets a 502. IP literals must be listed exactly.
- `state`: a Playwright storageState (`{cookies, origins: [{origin, localStorage}]}`), loaded before the call returns. It lives only in the service's memory and the container's tmpfs.
- `start_url`: the first tab goes there before the call returns (until the response arrives, not the load).

`GET /sessions` → `[{id, expires, closed}]`.

`GET /sessions/:id/cdp` — websocket: CDP of the whole browser, for `chromium.connectOverCDP(url, {headers})`. Use `browser.contexts()[0]` (the saved login is there).

`GET /sessions/:id/view` — the live view page: the browser's tabs, screencast, an address bar. It watches until the person presses Take control; then their mouse and keyboard go to the page. The page connects to the websockets `view/watch` and `view/drive` relative to its own URL (CDP like `cdp`; a `drive` connection is what counts as a person driving), so a proxy in front must pass those through, adding the key.

`GET /sessions/:id/log` → `[{t, method, url, status, blocked?, error?, live?}]`, every request the browser made, in order: `blocked` says why the proxy refused it (403), `error` why upstream failed (502), `live` that a person was driving. Works after the ttl too.

`GET /sessions/:id/screenshot` → PNG of the newest tab.

`GET|PUT /sessions/:id/files/<path>` — read or write a file in the container by absolute path (`PUT` makes the directories), such as `/files/tmp/x`. Downloads land where the agent's Playwright tells Chromium: `await download.path()` gives that path in the container (`/tmp/playwright-artifacts-…/<guid>`), so fetch `GET /sessions/:id/files/tmp/playwright-artifacts-…/<guid>`; `download.saveAs()` can't work, as the file isn't where the agent's Playwright runs.

`DELETE /sessions/:id` → `{state, log}`: the refreshed login (null if the browser was gone) and the whole request log; then the container is gone. A second `DELETE` is a 404.

## Notes for clients

- Playwright's `page.request` / `context.request` run in the agent's own process, not in the browser: they would leave from the agent's sandbox, not through this proxy. To use the page's cookies, fetch inside the page: `page.evaluate(u => fetch(u).then(r => r.text()), url)`.
- The proxy keeps to hosts, not to reads: whatever the session's login may do on its site, the browser may do. Every request is in `log`, with `live` when a person drove it.

## Open items

- **Chromium** still posts twice per session to `update.googleapis.com`; the proxy blocks both (log noise only).

## License

MIT, see [LICENSE](LICENSE).
