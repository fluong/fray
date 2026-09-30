#!/usr/bin/env bash
# Fail if action.yml has any uses: not pinned to a 40-char commit SHA.
# Missing action.yml or unreadable input → exit non-zero (fail closed).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
file="${root}/action.yml"

if [[ ! -f "$file" ]]; then
  echo "missing action.yml at $file" >&2
  exit 1
fi
if [[ ! -r "$file" ]]; then
  echo "action.yml not readable: $file" >&2
  exit 2
fi

# Match composite/workflow uses lines: "uses: owner/repo[/path]@ref" (optional comment).
unpinned=0
while IFS= read -r line || [[ -n "$line" ]]; do
  # Skip comments and blank lines.
  trimmed="${line#"${line%%[![:space:]]*}"}"
  [[ -z "$trimmed" || "$trimmed" == \#* ]] && continue
  if [[ "$trimmed" =~ ^uses:[[:space:]]+([^[:space:]]+) ]]; then
    ref="${BASH_REMATCH[1]}"
    # Strip trailing comment if glued (shouldn't be; YAML comment is after space).
    ref="${ref%%#*}"
    # Expect owner/name[/subdir]@<40 hex>
    if [[ ! "$ref" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$ ]]; then
      echo "unpinned uses: $ref" >&2
      echo "  (from: $trimmed)" >&2
      unpinned=1
    fi
  fi
done < "$file" || {
  echo "failed reading action.yml: $file" >&2
  exit 2
}

if [[ "$unpinned" -ne 0 ]]; then
  echo "action.yml: every uses: must be pinned to a 40-character commit SHA (e.g. owner/repo@deadbeef… # vX.Y.Z)" >&2
  exit 1
fi

echo "action.yml: all uses: pinned to 40-char SHAs"
