#!/usr/bin/env bash
# Generates test fixtures. random.bin (5 MiB), compressible.csv (10 MiB) and
# video-faststart.mp4 are committed; big.bin (50 MiB) is NOT committed.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p fixtures

if [ ! -s fixtures/random.bin ] || [ "$(stat -c%s fixtures/random.bin)" != 5242880 ]; then
  head -c 5242880 /dev/urandom > fixtures/random.bin
fi
if [ ! -s fixtures/compressible.csv ] || [ "$(stat -c%s fixtures/compressible.csv)" != 10485760 ]; then
  # exactly 10 MiB of very compressible rows: i,i*i,pad (streaming awk, no string accumulation)
  awk 'BEGIN {
    n = 0; total = 0; target = 10485760
    while (1) {
      line = sprintf("%d,%d,padding-padding-padding-padding-padding-padding\n", n, n*n)
      if (total + length(line) > target) {
        rem = target - total
        s = sprintf("%d,%d,", n, n*n)
        if (rem > 0) {
          if (length(s) >= rem) { printf "%s", substr(s, 1, rem) }
          else {
            printf "%s", s; rem -= length(s)
            p = "padding-padding-padding-padding-padding-padding"
            while (rem > 0) { q = (rem > length(p)) ? p : substr(p, 1, rem); printf "%s", q; rem -= length(q) }
          }
        }
        break
      }
      printf "%s", line
      total += length(line); n++
    }
  }' > fixtures/compressible.csv
fi

if [ ! -s fixtures/big.bin ]; then
  head -c 52428800 /dev/urandom > fixtures/big.bin
fi

if [ ! -s fixtures/video-faststart.mp4 ]; then
  if command -v ffmpeg >/dev/null 2>&1; then
    ffmpeg -y -loglevel error -f lavfi -i testsrc=duration=30:size=640x360:rate=24 \
      -f lavfi -i sine=frequency=440:duration=30 \
      -movflags +frag_keyframe+empty_moov+default_base_moof -pix_fmt yuv420p -c:v libx264 -c:a aac \
      fixtures/video-faststart.mp4
  else
    echo "warning: ffmpeg not found; video-faststart.mp4 not generated." >&2
    echo "Streaming tests must be skipped with a written reason." >&2
  fi
fi

ls -la fixtures/
