#!/bin/sh
export HOME=/tmp
socat TCP-LISTEN:3128,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:/run/machines/proxy.sock &
socat UNIX-LISTEN:/run/machines/cdp.sock,fork TCP:127.0.0.1:9222 &
exec chromium --headless --no-sandbox --disable-dev-shm-usage \
  --remote-debugging-address=127.0.0.1 --remote-debugging-port=9222 \
  --user-data-dir=/tmp/profile --window-size=1280,800 \
  --proxy-server=http://127.0.0.1:3128 --proxy-bypass-list='<-loopback>' \
  --ignore-certificate-errors-spki-list="$1" \
  --no-first-run --no-default-browser-check --disable-background-networking \
  --disable-component-update --disable-sync --metrics-recording-only about:blank
