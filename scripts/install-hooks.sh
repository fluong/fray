#!/usr/bin/env bash
# Point this clone at .githooks so pre-push runs actionlint, gitleaks, denylist,
# action.yml SHA pins, and the public-docs companion-name check.
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
echo "pre-push will refuse the push on actionlint, gitleaks, denylist, pin, or public-docs hits."
echo "Requires actionlint and gitleaks on PATH (brew install actionlint gitleaks)."
