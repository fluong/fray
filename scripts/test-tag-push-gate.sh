#!/usr/bin/env bash
# Contract tests for the v* tag CI gate peel logic in .githooks/pre-push.
# Run: ./scripts/test-tag-push-gate.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d "${root}/.tmp-tag-gate.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# Empty template avoids copying sample hooks.
git -C "$tmp" -c init.templateDir= init -q
git -C "$tmp" config user.email "tag-gate-test@example.com"
git -C "$tmp" config user.name "tag-gate-test"
echo content >"$tmp/f"
git -C "$tmp" add f
git -C "$tmp" -c commit.gpgsign=false commit -qm "base"
commit="$(git -C "$tmp" rev-parse HEAD)"

git -C "$tmp" tag "v0.0.0-light"
git -C "$tmp" -c tag.gpgsign=false tag -a "v0.0.0-ann" -m "v0.0.0-ann"

light_sha="$(git -C "$tmp" rev-parse "v0.0.0-light")"
ann_sha="$(git -C "$tmp" rev-parse "v0.0.0-ann")"
light_commit="$(git -C "$tmp" rev-parse "${light_sha}^{commit}")"
ann_commit="$(git -C "$tmp" rev-parse "${ann_sha}^{commit}")"

if [[ "$(git -C "$tmp" cat-file -t "$light_sha")" != "commit" ]]; then
  echo "FAIL: lightweight tag should resolve to a commit object" >&2
  exit 1
fi
if [[ "$(git -C "$tmp" cat-file -t "$ann_sha")" != "tag" ]]; then
  echo "FAIL: annotated tag should resolve to a tag object" >&2
  exit 1
fi
if [[ "$light_commit" != "$commit" || "$ann_commit" != "$commit" ]]; then
  echo "FAIL: peel mismatch light=${light_commit} ann=${ann_commit} want=${commit}" >&2
  exit 1
fi
if [[ "$ann_sha" == "$commit" ]]; then
  echo "FAIL: annotated tag object sha should differ from commit" >&2
  exit 1
fi
echo "ok: lightweight + annotated peel to ${commit}"

# Simulate the gate's gh lookup + conclusion check (empty runs → refuse).
classify_runs() {
  python3 -c '
import json, sys
runs = json.load(sys.stdin)
latest = {}
for r in runs:
    name = r.get("name") or ""
    if name and name not in latest:
        latest[name] = r.get("conclusion") or ""
need = ("guardrails", "test")
missing = [n for n in need if latest.get(n) != "success"]
if missing:
    sys.exit(1)
'
}

if printf '%s' '[]' | classify_runs; then
  echo "FAIL: empty runs must be refused" >&2
  exit 1
fi
echo "ok: empty runs refused"

# Peeling a bogus sha fails closed (same as the hook).
if git -C "$tmp" rev-parse "0000000000000000000000000000000000000001^{commit}" >/dev/null 2>&1; then
  echo "FAIL: expected peel of missing object to fail" >&2
  exit 1
fi
echo "ok: peel failure fails closed"

# Sanity: pre-push contains the peel before gh run list.
if ! grep -q 'rev-parse "${local_sha}^{commit}"' "$root/.githooks/pre-push"; then
  echo "FAIL: .githooks/pre-push missing annotated-tag peel" >&2
  exit 1
fi
if ! grep -q 'tag object .* → commit' "$root/.githooks/pre-push"; then
  echo "FAIL: .githooks/pre-push missing peel log line" >&2
  exit 1
fi
echo "ok: pre-push peels before CI lookup"
