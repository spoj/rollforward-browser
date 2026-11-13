# rollforward-browser

Browsers for an agent's bounded task on one website or a person's open sign-in, then thrown away. Shared by [rollforward](https://github.com/spoj/rollforward) servers, each holding its own client key and seeing only its own sessions.

Each session is a podman container with Chromium, driven over CDP (Playwright `connectOverCDP`), with Noto fonts, Chinese, Japanese and Korean included, Liberation's and Carlito, Calibri's metric twin, so pages show, print and screenshot as written. The container has no network (`--network none`), its own read-only image, and its home and profile in memory (`/tmp`, tmpfs). Its only way out is a proxy in this service, reached over a unix socket: the proxy ends TLS itself (the browser accepts exactly this service's key), so it sees every request whole, keeps to the site's hosts (or public hosts for an open sign-in session) and logs each request. Chromium's own calls, such as its updaters', autofill's and its leak check of the passwords people sign in with, are switched off (`browser/`), so a log holds only what the session's pages asked for.

## Run

Needs Node 26 and rootless podman (tested with 6.1).

    podman build -t rollforward-browser browser
    npm install
    BROWSER_KEY=$(openssl rand -hex 32) node src/server.ts

Where the image can't be built, as on a host that can't reach Debian's mirrors, pull the one each tag publishes and give it the name the service runs: `podman pull ghcr.io/spoj/rollforward-browser:TAG && podman tag ghcr.io/spoj/rollforward-browser:TAG rollforward-browser`.

It listens on `BROWSER_HOST` (default 127.0.0.1), port `BROWSER_PORT` (default 8797). Each client's key is rollforward's `RF_BROWSER_KEY`, with `RF_BROWSER_URL` its address. `curl -H "authorization: Bearer $BROWSER_KEY" http://127.0.0.1:8797/sessions` answers `[]` when it's up. Leftovers of an earlier run on the same port (containers, runtime files) are removed at start. `NODE_EXTRA_CA_CERTS` adds CAs the proxy trusts upstream (an ERP with an internal CA).

`BROWSER_KEYS` is a whitespace-separated list of `name:key` pairs, such as `accounts:SECRET1 support:SECRET2`. Names use `a-z`, `0-9`, `-`; names and keys must be unique. When set, it replaces `BROWSER_KEY`; `BROWSER_KEY` alone is one client named `default`, unchanged for existing deployments. Keys are compared in constant time. The updater uses the first key.

`BROWSER_BLOCKLISTS` is a whitespace-separated list of URLs of text files, one domain per line (`#` comments and blank lines skipped). The default is [HaGeZi's threat intelligence list](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt). Lists are fetched at startup and every 24 hours, kept only in memory; a failed fetch keeps the previous combined set, and with none yet is tried again each minute. A file that is empty or has a line that isn't a domain, such as an HTML page, fails the fetch, as does a combined set under half the size of the one in use. A domain covers its subdomains, case-insensitively, with a trailing dot ignored.

Run it as a user of its own, next to rollforward's: CDP is close to code execution in the container, whose user is the service's user (`--userns keep-id`). As a systemd user service of that user, with lingering on (`loginctl enable-linger USER`):

    # ~/.config/systemd/user/rollforward-browser.service
    [Service]
    WorkingDirectory=%h/rollforward-browser
    EnvironmentFile=%h/.config/rollforward-browser.env
    ExecStart=/usr/bin/node src/server.ts
    Restart=on-failure

    [Install]
    WantedBy=default.target

with `BROWSER_KEY=...` (or `BROWSER_KEYS="accounts:... support:..."`) in `~/.config/rollforward-browser.env`, then `systemctl --user enable --now rollforward-browser`. `ExecStart` names Node 26 where it is, such as `/opt/node-v26/bin/node` beside an older system node.

**Updates come by themselves.** `scripts/update.ts` moves the checkout to the newest GitHub Release once every check on its commit has passed. CI makes one from each tag whose tests pass, after pushing its image; a tag with a `Manual:` line in its message makes a prerelease, which the updater stops before, for a person to deploy by hand. If the release changed `browser/`, the updater pulls its image first, however long that takes, and switches code and image together; otherwise the running image stays, so a new Chromium comes only with a change to `browser/`. Its packages are fetched first too, into npm's cache, so a failure there, as without the network, changes nothing and the next tick tries again. It drains the service first: on SIGUSR2 the service opens no session, and once every open one has been collected, its request log with it, or 30 minutes have passed, `GET /drained` answers 200. Then it moves code and image and restarts the service; if the service doesn't answer, code and image go back, and that release isn't tried again, and if going back fails too, the service restarts as the checkout is. A checkout on no release tag, as after a person's fix by hand, stops updates until one is checked out again. It asks GitHub without a token, so every 15 minutes, as a timer of the same user:

    # ~/.config/systemd/user/rollforward-browser-update.service
    [Service]
    Type=oneshot
    WorkingDirectory=%h/rollforward-browser
    EnvironmentFile=%h/.config/rollforward-browser.env
    Environment=PATH=/opt/node-v26/bin:/usr/bin
    ExecStart=/opt/node-v26/bin/node scripts/update.ts
    TimeoutStartSec=3h

    # ~/.config/systemd/user/rollforward-browser-update.timer
    [Timer]
    OnBootSec=5min
    OnUnitActiveSec=15min

    [Install]
    WantedBy=timers.target

then `systemctl --user enable --now rollforward-browser-update.timer`; `journalctl --user -u rollforward-browser-update` shows what it did. A restart without the drain ends the browsers open at the time, and their logs with them.

On a host of its own, such as a VM next to rollforward's:

- **Listen on the private interface:** `BROWSER_HOST`, an IPv4 address of this host, such as `10.0.0.5`.
- **Let only the rollforward host in:** a firewall rule allowing its address to `BROWSER_PORT`, and nothing else.
- **Encrypt the link:** CDP and the live view carry signed-in sessions, and the key goes with every request. Either listen on a private link, WireGuard or Tailscale, and give rollforward its `http://` address there; or keep `BROWSER_HOST` at 127.0.0.1 behind a reverse proxy that ends TLS and passes websockets, such as Caddy, and give rollforward its `https://` address (with `NODE_EXTRA_CA_CERTS` on the rollforward host for a private CA).
- **The sites are reached from here:** browsers' requests leave from this host, so it needs the routes to the sites (the ERP, the portals), or to their `via` proxy, and, for an internal CA, `NODE_EXTRA_CA_CERTS`; the rollforward host doesn't.
- **Sizing:** a browser container is capped at 2 GB, about 0.2 GB idle and more on heavy sites.

Tests: `npm test` (needs the image).

## API

Every request carries `Authorization: Bearer <client-key>`. Sessions belong to the client that opened them; another client's session is a 404 on every session route and websocket, even after its ttl. `/blocked` and `/drained` are shared, available to every client. Errors are `{error}` with a status: 400 (a site, or hosts, the service can't use), 401, 404 (no such session, route or file), 410 (the session's ttl ran out), 503 (the blocklists aren't loaded yet, or a new session while the service drains for an update), 500.

`POST /sessions` `{site: {hosts, start_url?, headers?, public?, open?, except?, via?}, state?, ttl_s?}` → 201 `{id, cdp, view}` (paths on this service). After `ttl_s` (default 3600) the session closes on its own; its result waits for `DELETE`.

- `hosts`: names the browser may reach, exact (`erp.example`) or `*.example` for any name under it, not the domain itself, as ASCII (punycode for an IDN) without a trailing dot, or an IPv6 literal in brackets. Anything else gets a 403 page unless `open` is true. Send `hosts: []` for an open session with no explicitly allowed hosts.
- `open: true`: a person's sign-in may reach unlisted names at public addresses, over https only, without allowing each SSO or CDN host by hand. Every request, even to a listed host, is refused with a 403 if the host or a parent domain is on a blocklist (`blocked: "on a blocklist"`). Before the first successful blocklist load, opening such a session answers 503 `{error: "blocklists not loaded yet"}`. The client should set a short `ttl_s` for a sign-in; the default is unchanged.
- `except`: exact names or `*.example` patterns an open session must not reach (403, `blocked: "host not on the list"`), even if listed in `hosts` or later added with `PUT`. Matching is case-insensitive and ignores a trailing dot on the requested host. `except` is checked before blocklists; neither applies to non-open sessions. Listed hosts bypass neither restriction nor the https requirement; exact hosts of a non-`public` open site keep their existing intranet access.
- `via`: `{url, token, hosts}`. Requests to these exact names or `*.example` patterns (matching as `except` does) use the upstream proxy at `url` (`http://host:port` or `https://host:port`); other hosts stay direct. Each connection sends `CONNECT host:port` with `Proxy-Authorization: Bearer <token>`, then TLS for https/wss, or plain HTTP for http/ws, inside the tunnel. The target name is resolved on the far side, never here, so local internal-address rules do not apply to these hosts, including for a `public` site. `via` grants no host permission: `hosts`/`open`, `except`, blocklists and https rules still apply, including after `PUT /hosts`; every request is logged as before, websockets too. A proxy refusal or connection failure gives the request a 502 with the reason in the log's `error`. The token is held only in the session's memory, never sent to the browser, logged or returned by a route; `via` is fixed when the session opens. A client's VPN held elsewhere, offered as a proxy; this service knows nothing of VPNs.
- For direct connections, internal addresses (private, CGNAT, unique-local) are reachable only through a name listed exactly, as an intranet's are, and through none for a `public` site, a person's own rather than an admin's: a name that may not reach them and resolves only to them gets a 502. Direct connections never reach a loopback or link-local address, or Azure's WireServer. IP literals must be listed exactly, and are held to the same rules, an address a listed one may not reach getting a 403 (`blocked: "internal address"`).
- Each direct connection goes to one address, IPv4 where the host has one, with no racing of IPv4 against IPv6: a machine with no IPv6 route needs nothing set, where Node's own happy eyeballs would fail requests whenever IPv4 answered slowly.
- `state`: a Playwright storageState (`{cookies, origins: [{origin, localStorage}]}`), loaded before the call returns. It lives only in the service's memory and the container's tmpfs.
- `start_url`: the first tab goes there before the call returns (until the response arrives, not the load).
- `headers`: `{name: value}`, added by the proxy to every request to `start_url`'s origin and no other, such as a token a site's sign-in needs that its pages never send. The browser never holds them, so nothing on its CDP can read them, and the log doesn't record headers.

`PUT /sessions/:id/hosts` `{hosts}` → 200 `{hosts}`: the session's hosts from then on, as a person allows another a page of it was refused. `POST /sessions/:id/reload` loads the newest tab again.

A `public` or `open` site's requests go over https only; any other gets a 403 (`blocked: "https only"`). IP literals are never allowed just by `open`: they must be in `hosts` exactly.

`GET /blocked?host=a.example&host=b.example` → 200 `{"a.example": true, "b.example": false}`: whether each host or a parent domain is on a blocklist. Before the first successful load it answers 503 `{error: "blocklists not loaded yet"}`; ordinary sessions are unaffected.

`GET /sessions` → `[{id, expires, closed}]`: only this client's sessions, including those past their ttl until collected. A client may collect these at startup without disturbing another's.

`GET /sessions/:id/cdp` — websocket: CDP of the whole browser, for `chromium.connectOverCDP(url, {headers})`. Use `browser.contexts()[0]` (the saved login is there).

`GET /sessions/:id/view` — the live view page: the browser's tabs, screencast, an address bar. It watches until the person presses Take control, or from the start with `?drive`; then their mouse and keyboard go to the page. With `?watch` it only watches, with no control to take. The page connects to the websockets `view/watch` and `view/drive` relative to its own URL, so a proxy in front must pass those through, adding the key. `view/drive` is CDP like `cdp`, and what counts as a person driving. `view/watch` passes only what watching asks, the tabs and a screencast of one: `Target.setDiscoverTargets`, `Target.attachToTarget`, `Target.detachFromTarget`, `Page.startScreencast`, `Page.stopScreencast` and `Page.screencastFrameAck`, each sent on as its JSON parsed and written again, uncompressed. Anything else, such as input or a script, ends the socket, so a watcher, such as someone watching a run's browser, can't drive it.

`GET /sessions/:id/log` → `[{t, method, url, status, dest?, from?, blocked?, error?, live?}]`, every request the browser made, in order: `dest` is its kind as the browser sent it (`Sec-Fetch-Dest`: `document`, `iframe`, `script`, `style`, `image`, `font`, or `empty` for a page's own fetch), `from` the page it came from (`Referer`, which another site's request carries as its origin alone), each where the browser sent it; `blocked` says why the proxy refused it (403), `error` why upstream failed (502), `live` that a person was driving. Works after the ttl too.

`GET /sessions/:id/screenshot` → PNG of the newest tab.

`GET /sessions/:id/page` → `{url, password}`: the newest tab once loaded, its address and whether it shows a password field, as a sign-in page does; for a client keeping a login alive, which loads a page in it and finds the session over if it shows a sign-in.

`GET|PUT /sessions/:id/files/<path>` — read or write a file in the container by absolute path (`PUT` makes the directories), such as `/files/tmp/x`. Downloads land where the agent's Playwright tells Chromium: `await download.path()` gives that path in the container (`/tmp/playwright-artifacts-…/<guid>`), so fetch `GET /sessions/:id/files/tmp/playwright-artifacts-…/<guid>`; `download.saveAs()` can't work, as the file isn't where the agent's Playwright runs.

`DELETE /sessions/:id` → `{state, log}`: the refreshed login (null if the browser was gone) and the whole request log; then the container is gone. A second `DELETE` is a 404.

`GET /drained` → 200 once the service, sent SIGUSR2, has had every session collected or drained for 30 minutes; 503 before, with `{open}`, the total sessions not yet collected across all clients.

## Notes for clients

- Playwright's `page.request` / `context.request` run in the agent's own process, not in the browser: they would leave from the agent's sandbox, not through this proxy. To use the page's cookies, fetch inside the page: `page.evaluate(u => fetch(u).then(r => r.text()), url)`.
- The proxy keeps to the site's host policy, not to reads: whatever the session's login may do on its site, the browser may do. Every request is in `log`, with `live` when a person drove it.
- Pages see a browser without passkeys: no `PublicKeyCredential`, and `navigator.credentials.get` or `create` with `publicKey` fails at once with `NotAllowedError`, as when a person cancels. A passkey needs a window of the browser's own, for Windows Hello, a security key or a phone, which a headless browser never shows, so a page asking for one, such as Microsoft's sign-in for an account that has one, would wait for good; this way it signs in another way, such as a password or an authenticator app.

## License

MIT, see [LICENSE](LICENSE).
