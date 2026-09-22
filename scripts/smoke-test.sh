#!/usr/bin/env bash
# End-to-end smoke test: run the built jar and verify it decrypts the flag
# correctly with the (known-good, since we built it) key path.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

JAR="target/Anwendung.jar"
if [ ! -f "$JAR" ]; then
  echo "smoke-test: $JAR not found -- run scripts/build.sh first" >&2
  exit 1
fi

OUT_FILE="$(mktemp -t securevault-flag.XXXXXX)"
trap 'rm -f "$OUT_FILE"' EXIT

echo "== running: java -jar $JAR --decrypt --out $OUT_FILE =="
java -jar "$JAR" --decrypt --out "$OUT_FILE"

if [ ! -s "$OUT_FILE" ]; then
  echo "smoke-test FAILED: output file is empty" >&2
  exit 1
fi

DECRYPTED="$(cat "$OUT_FILE")"
echo "decrypted content: $DECRYPTED"

if [[ "$DECRYPTED" != FLAG\{*\} ]]; then
  echo "smoke-test FAILED: decrypted content does not look like a flag" >&2
  exit 1
fi

echo "== --help output =="
java -jar "$JAR" --help

echo "smoke-test OK"
