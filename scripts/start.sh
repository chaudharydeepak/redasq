#!/usr/bin/env bash
# Build redasq if needed, then run it. The classifier sidecar is spawned
# automatically by the binary — no extra setup required. Pass --no-ml to
# skip the classifier, or --ml-url=<url> to point at an external one.

set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -x redasq ]] || [[ main.go -nt redasq ]]; then
  echo "→ building redasq..."
  go build -o redasq .
fi

exec ./redasq "$@"
