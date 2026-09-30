#!/usr/bin/env bash
# Point this clone at .githooks so pre-push runs gitleaks, denylist, and action.yml SHA pins.
# Same checks as .github/workflows/guardrails.yml.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "not a git repository: $root" >&2
  exit 1
fi

git config core.hooksPath .githooks
echo "Installed: core.hooksPath=.githooks"
echo "pre-push will refuse the push on gitleaks or denylist hits."
echo "Requires gitleaks on PATH (brew install gitleaks)."
