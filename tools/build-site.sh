#!/usr/bin/env bash
# Build both books into ./site : English at the root, Chinese under /zh/.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EN="$ROOT/.build-en"
ZH="$ROOT/.build-zh"
OUT="$ROOT/site"

rm -rf "$EN" "$ZH" "$OUT"
mdbook build "$ROOT/book-en" -d "$EN"
mdbook build "$ROOT/book-zh" -d "$ZH"

mkdir -p "$OUT/zh"
cp -R "$EN"/. "$OUT"/
cp -R "$ZH"/. "$OUT/zh"/
echo "site built at $OUT"
