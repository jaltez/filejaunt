#!/usr/bin/env bash
# Downloads the EFF large wordlist (diceware, public domain) into assets/.
# Aborts unless the file has exactly 7776 lines.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p assets
URL="https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
for attempt in 1 2 3; do
  if curl -fsSL --retry 2 -o "$TMP" "$URL"; then break; fi
  if [ "$attempt" = 3 ]; then echo "error: cannot download $URL" >&2; exit 1; fi
  sleep 2
done
# strip any BOM/CR, keep "word" column (lines look like "11111\tabacus")
LINES="$(tr -d '\r' < "$TMP" | awk -F'\t' 'NF>=2 {print $2}' | tee assets/wordlist-eff.txt | wc -l)"
if [ "$LINES" != "7776" ]; then
  echo "error: expected 7776 words, got $LINES" >&2
  rm -f assets/wordlist-eff.txt
  exit 1
fi
echo "ok: assets/wordlist-eff.txt ($LINES words)"
