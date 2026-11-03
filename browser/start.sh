#!/bin/sh
export HOME=/tmp
# Chromium asks update.googleapis.com for its on-device AI models' manifest even with component updates off, unless told of one
# that names none.
printf '{}' > /tmp/models.json
socat TCP-LISTEN:3128,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:/run/rollforward-browser/proxy.sock &
socat UNIX-LISTEN:/run/rollforward-browser/cdp.sock,fork TCP:127.0.0.1:9222 &
exec /usr/lib/chromium/chromium --headless --no-sandbox --disable-dev-shm-usage \
  --remote-debugging-address=127.0.0.1 --remote-debugging-port=9222 \
  --user-data-dir=/tmp/profile --window-size=1280,800 \
  --proxy-server=http://127.0.0.1:3128 --proxy-bypass-list='<-loopback>' \
  --ignore-certificate-errors-spki-list="$1" \
  --no-first-run --no-default-browser-check --no-service-autorun --password-store=basic \
  --disable-field-trial-config --disable-background-networking --disable-component-update \
  --disable-component-extensions-with-background-pages --disable-client-side-phishing-detection \
  --disable-default-apps --disable-extensions --disable-sync --disable-breakpad --metrics-recording-only \
  --disable-search-engine-choice-screen --disable-back-forward-cache --optimization-guide-manifest-override=/tmp/models.json \
  --disable-background-timer-throttling --disable-backgrounding-occluded-windows --disable-renderer-backgrounding \
  --disable-features=OptimizationHints,NetworkTimeServiceQuerying,AimEnabled,Translate,MediaRouter,DialMediaRouteProvider,HttpsUpgrades,LensOverlay,AutofillServerCommunication \
  about:blank
