#!/usr/bin/env bash
# Build the web library + reference app, then publish the library to the local
# filejaunt.com checkout (served verbatim) plus a sha256 sidecar.
#
# The site owns its own UI (app/index.html + app/app.js); only the built
# library (app/fj.js) is overwritten here. The reference example stays in the
# core repo as web/dist/filejaunt.html.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> building wasm"
wasm-pack build crates/fj-wasm --target web --out-dir pkg --out-name filejaunt_wasm

echo "==> building web library + example"
(cd web && node build.mjs)

LIB=web/dist/fj.js
test -s "$LIB" || { echo "error: $LIB missing" >&2; exit 1; }
SIZE=$(stat -c%s "$LIB")
echo "==> library: $LIB ($SIZE bytes)"

DEST=../filejaunt.com/app
if mkdir -p "$DEST" 2>/dev/null; then
  cp "$LIB" "$DEST/fj.js"
  (cd "$DEST" && sha256sum fj.js > sha256.txt)
  echo "==> published to $DEST"
else
  echo "warning: cannot write $DEST (permissions); library stays in web/dist/" >&2
fi
