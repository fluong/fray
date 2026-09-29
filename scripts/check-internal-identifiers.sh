#!/usr/bin/env bash
# Fail if fray-server internal identifiers appear in the public tree.
#
# One script for CI and local hooks — scans the whole working tree, including
# *_test.go and other fixtures. Do not narrow the path set for a "local" check.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

patterns=(
  'fray-509910'
  'fray-run@'
  'fray-scan-archive'
  'fray-api-'
  'neon\.tech'
  'r2\.cloudflarestorage'
)

# Exclude only the denylist itself and hook/CI plumbing that cite the patterns.
# Never exclude *_test.go, testdata/, or goldens.
exclude=(
  --glob '!.git/**'
  --glob '!scripts/check-internal-identifiers.sh'
  --glob '!.github/workflows/guardrails.yml'
  --glob '!.githooks/**'
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
