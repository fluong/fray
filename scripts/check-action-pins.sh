#!/usr/bin/env bash
# Fail if any uses: in action.yml, .github/workflows/**, README.md, or docs/**
# is not pinned to exactly 40 lowercase hex characters.
# Exempt only local ./ paths and docker://… refs.
# Missing/unreadable inputs → exit non-zero (fail closed).
#
# Override scan root with FRAY_ACTION_PINS_ROOT (for tests).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -n "${FRAY_ACTION_PINS_ROOT:-}" ]]; then
  root="$(cd "${FRAY_ACTION_PINS_ROOT}" && pwd)"
fi

files=()
if [[ -f "${root}/action.yml" ]]; then
  files+=("${root}/action.yml")
fi
if [[ -f "${root}/README.md" ]]; then
  files+=("${root}/README.md")
fi
if [[ -d "${root}/.github/workflows" ]]; then
  while IFS= read -r f; do
    [[ -n "$f" ]] && files+=("$f")
  done < <(find "${root}/.github/workflows" \( -name '*.yml' -o -name '*.yaml' \) -type f | LC_ALL=C sort)
fi
if [[ -d "${root}/docs" ]]; then
  while IFS= read -r f; do
    [[ -n "$f" ]] && files+=("$f")
  done < <(find "${root}/docs" -name '*.md' -type f | LC_ALL=C sort)
fi

if [[ ${#files[@]} -eq 0 ]]; then
  echo "no action.yml, workflows, README.md, or docs/** to check under ${root}" >&2
  exit 1
fi

# owner/name[/subdir]@<exactly 40 lowercase hex>
sha_pin_re='^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$'

unpinned=0
checked=0
for file in "${files[@]}"; do
  if [[ ! -r "$file" ]]; then
    echo "not readable: $file" >&2
    exit 2
  fi
  rel="${file#"${root}/"}"
  line_no=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_no=$((line_no + 1))
    trimmed="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$trimmed" || "$trimmed" == \#* ]] && continue
    if [[ "$trimmed" =~ ^-?[[:space:]]*uses:[[:space:]]+([^[:space:]]+) ]]; then
      ref="${BASH_REMATCH[1]}"
      ref="${ref%%#*}"
      checked=$((checked + 1))
      if [[ "$ref" == ./* ]]; then
        continue
      fi
      if [[ "$ref" == docker://* ]]; then
        continue
      fi
      if [[ "$ref" =~ $sha_pin_re ]]; then
        continue
      fi
      echo "unpinned uses: ${rel}:${line_no}: $ref" >&2
      unpinned=1
    fi
  done < "$file" || {
    echo "failed reading: $file" >&2
    exit 2
  }
done

if [[ "$checked" -eq 0 ]]; then
  echo "no uses: lines found under ${root}" >&2
  exit 1
fi

if [[ "$unpinned" -ne 0 ]]; then
  echo "every uses: must be owner/repo@<40 lowercase hex> (optional # comment)," >&2
  echo "a local ./ path, or docker://… — placeholders, tags, branches, and short SHAs fail" >&2
  exit 1
fi

echo "ok: ${checked} uses: pin(s) across ${#files[@]} file(s)"
