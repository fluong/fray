#!/usr/bin/env bash
# Fail if public docs name the private companion repository, or if README /
# docs / action.yml contain a Cloud Run *.run.app hostname/URL
# (use https://api.getfray.dev). Mentions like "*.run.app" in prose are OK;
# only real hostnames (e.g. service-xx.a.run.app) fail.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if ! command -v grep >/dev/null 2>&1; then
  echo "check-public-docs requires grep on PATH" >&2
  exit 2
fi

hits=0

check_pattern() {
  local pattern="$1"
  local label="$2"
  shift 2
  local f matches status
  for f in "$@"; do
    if [[ ! -f "$f" ]]; then
      echo "missing $f" >&2
      exit 2
    fi
    set +e
    matches="$(grep -nE "$pattern" "$f")"
    status=$?
    set -e
    case "$status" in
      0)
        echo "$matches" >&2
        echo "forbidden: $f must not contain ${label}" >&2
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
}

check_pattern 'fray-server' 'companion repo name fray-server' CHANGELOG.md README.md

# Real Cloud Run hostnames only (not the prose token "*.run.app").
run_app_pattern='[a-z0-9][a-z0-9.-]*\.run\.app'
run_app_files=(README.md action.yml)
if [[ -d docs ]]; then
  while IFS= read -r -d '' f; do
    run_app_files+=("$f")
  done < <(find docs -type f \( -name '*.md' -o -name '*.yml' -o -name '*.yaml' \) -print0 | sort -z)
fi
check_pattern "$run_app_pattern" 'Cloud Run *.run.app hostname (use https://api.getfray.dev)' "${run_app_files[@]}"

if [[ "$hits" -ne 0 ]]; then
  exit 1
fi

echo "public docs: no companion-repo name; no run.app hostnames"
