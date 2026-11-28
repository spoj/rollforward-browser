#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RF_DIR="${1:-$REPO_ROOT/../rollforward}"
SRC_DIR="$RF_DIR/src/shared"
DST_DIR="$REPO_ROOT/src/shared"
FILES=(classify.ts redact.ts)

for f in "${FILES[@]}"; do
  if [[ ! -f "$SRC_DIR/$f" ]]; then
    echo "error: missing source file $SRC_DIR/$f" >&2
    echo "usage: $0 [path-to-rollforward-repo]" >&2
    exit 1
  fi
done

mkdir -p "$DST_DIR"
for f in "${FILES[@]}"; do
  cp "$SRC_DIR/$f" "$DST_DIR/$f"
done

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$DST_DIR" && sha256sum "${FILES[@]}" > SHA256SUMS)
else
  (cd "$DST_DIR" && shasum -a 256 "${FILES[@]}" > SHA256SUMS)
fi

cat "$DST_DIR/SHA256SUMS"
