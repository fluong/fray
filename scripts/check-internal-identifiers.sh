#!/usr/bin/env bash
# Fail if fray-server internal identifiers appear in the public tree.
#
# One script for CI and local hooks — scans the whole working tree, including
# *_test.go and other fixtures. Do not narrow the path set for a "local" check.
#
# Patterns are NOT stored in this public repo. Load from (first match wins):
#   CI:    FRAY_DENYLIST secret only (missing/empty → fail)
#   local: FRAY_DENYLIST env → ~/.config/fray/denylist → fail closed
# Each source is newline-separated ERE patterns (grep -E); blank lines and
# # comments are ignored. Fail closed if no source is present or the list is empty.
#
# Search tool: grep -rnE (no hard dependency on rg). Missing grep → exit 2.
# Per-pattern exit codes: 0 = match (fail the check), 1 = no match (ok),
# anything else = tool/IO error → exit non-zero (never treat as clean).
#
# On a hit under GITHUB_ACTIONS: print only "<file>:<line> matches denylist
# entry #<n>" — never the matched text or the pattern. Local runs keep full
# grep output and the pattern in the hit line.
set -euo pipefail

if ! command -v grep >/dev/null 2>&1; then
  echo "denylist search requires grep on PATH" >&2
  exit 2
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

ci=0
[[ -n "${GITHUB_ACTIONS:-}" ]] && ci=1

load_patterns() {
  local raw=""
  if [[ "$ci" -eq 1 ]]; then
    # CI: secret only — never fall through to a runner home file.
    if [[ -z "${FRAY_DENYLIST:-}" ]]; then
      echo "denylist missing: set repository secret FRAY_DENYLIST" >&2
      exit 1
    fi
    raw="$FRAY_DENYLIST"
  elif [[ -n "${FRAY_DENYLIST:-}" ]]; then
    raw="$FRAY_DENYLIST"
  elif [[ -f "${HOME}/.config/fray/denylist" ]]; then
    raw="$(cat "${HOME}/.config/fray/denylist")"
  else
    echo "denylist missing: set FRAY_DENYLIST, or create ~/.config/fray/denylist" >&2
    exit 1
  fi

  patterns=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    # trim CR (Windows) and leading/trailing whitespace
    line="${line%$'\r'}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    patterns+=("$line")
  done <<<"$raw"

  if [[ "${#patterns[@]}" -eq 0 ]]; then
    echo "denylist empty: refusing to run open" >&2
    exit 1
  fi
}

load_patterns

hits=0
entry=0
for pat in "${patterns[@]}"; do
  entry=$((entry + 1))
  # Capture status explicitly: under set -e, grep's "no match" (1) must not
  # abort, and tool errors (2+) must not be treated as a clean scan.
  set +e
  if [[ "$ci" -eq 1 ]]; then
    # Suppress matched text on CI; only file:line are reported below.
    matches="$(grep -rnE --exclude-dir=.git -e "$pat" .)"
    status=$?
  else
    grep -rnE --exclude-dir=.git -e "$pat" .
    status=$?
    matches=""
  fi
  set -e
  case "$status" in
    0)
      if [[ "$ci" -eq 1 ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
          [[ -z "$line" ]] && continue
          file="${line%%:*}"
          rest="${line#*:}"
          lineno="${rest%%:*}"
          echo "${file}:${lineno} matches denylist entry #${entry}" >&2
        done <<<"$matches"
      else
        echo "denylist hit: $pat" >&2
      fi
      hits=1
      ;;
    1)
      ;; # no match
    *)
      if [[ "$ci" -eq 1 ]]; then
        echo "denylist search failed (exit ${status}) for denylist entry #${entry}" >&2
      else
        echo "denylist search failed (exit ${status}) for pattern: $pat" >&2
      fi
      exit "$status"
      ;;
  esac
done

if [[ "$hits" -ne 0 ]]; then
  echo "Internal identifiers must not appear in the public fray repo." >&2
  echo "Copy fray-server → fray with an explicit allowlist only." >&2
  exit 1
fi

echo "internal-identifier denylist: clean"
