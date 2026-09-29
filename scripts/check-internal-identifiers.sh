#!/usr/bin/env bash
# Fail if fray-server internal identifiers appear in the public tree.
#
# One script for CI and local hooks — scans the whole working tree, including
# *_test.go and other fixtures. Do not narrow the path set for a "local" check.
#
# Patterns are NOT stored in this public repo. Load from (first match wins):
#   CI:    FRAY_DENYLIST secret only (missing/empty → fail)
#   local: FRAY_DENYLIST env → ~/.config/fray/denylist → fail closed
# Each source is newline-separated ripgrep patterns; blank lines and # comments
# are ignored. Fail closed if no source is present or the list is empty.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

load_patterns() {
  local raw=""
  if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
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

# Exclude VCS only. Never exclude *_test.go, testdata/, or goldens.
exclude=(
  --glob '!.git/**'
)

hits=0
for pat in "${patterns[@]}"; do
  if rg -n --hidden "${exclude[@]}" -e "$pat" .; then
    echo "denylist hit: $pat" >&2
    hits=1
  fi
done

if [[ "$hits" -ne 0 ]]; then
  echo "Internal identifiers must not appear in the public fray repo." >&2
  echo "Copy fray-server → fray with an explicit allowlist only." >&2
  exit 1
fi

echo "internal-identifier denylist: clean"
