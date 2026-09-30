#!/usr/bin/env bash
# Fail if public docs name the private companion repository.
# Keeps the companion repo name out of the Go-module zip / GitHub UI surface.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if ! command -v grep >/dev/null 2>&1; then
  echo "check-public-docs requires grep on PATH" >&2
  exit 2
fi

forbidden='fray-server'
hits=0
for f in CHANGELOG.md README.md; do
  if [[ ! -f "$f" ]]; then
    echo "missing $f" >&2
    exit 2
  fi
  set +e
  matches="$(grep -nE "$forbidden" "$f")"
  status=$?
  set -e
  case "$status" in
    0)
      echo "$matches" >&2
      echo "forbidden: $f must not mention ${forbidden}" >&2
      hits=1
      ;;
    1)
      ;; # no match
    *)
      echo "grep failed (exit ${status}) scanning $f" >&2
      exit "$status"
      ;;
  esac
done

if [[ "$hits" -ne 0 ]]; then
  exit 1
fi

echo "public docs: no companion-repo name"
