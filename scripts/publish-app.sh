#!/usr/bin/env bash
# Build the single-file web app and publish it to the local filejaunt.com
# checkout (served verbatim; no design) plus a sha256 sidecar.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> building wasm"
wasm-pack build crates/fj-wasm --target web --out-dir pkg --out-name filejaunt_wasm

echo "==> building web app"
(cd web && node build.mjs)

OUT=web/dist/filejaunt.html
test -s "$OUT" || { echo "error: $OUT missing" >&2; exit 1; }
SIZE=$(stat -c%s "$OUT")
echo "==> artifact: $OUT ($SIZE bytes)"
if [ "$SIZE" -gt $((5 * 1024 * 1024)) ]; then
  echo "note: single-file artifact exceeds 5 MiB (kept single-file by design)"
fi

sha256sum "$OUT" | awk '{print $1}' > web/dist/filejaunt.html.sha256

DEST=../filejaunt.com/app
if mkdir -p "$DEST" 2>/dev/null; then
  cp "$OUT" "$DEST/index.html"
  cp web/dist/filejaunt.html.sha256 "$DEST/sha256.txt"
  echo "==> published to $DEST"
else
  echo "warning: cannot write $DEST (permissions); artifact stays in web/dist/" >&2
fi
