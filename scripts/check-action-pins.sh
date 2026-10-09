#!/usr/bin/env bash
# Fail if any uses: in action.yml, .github/workflows/*.yml, README.md, or
# docs/*.md is not pinned to a 40-character commit SHA (or the docs placeholder
# <full-commit-sha>). Local actions (./…) and docker://…@sha256:… are allowed.
# Missing/unreadable inputs → exit non-zero (fail closed).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"

files=()
if [[ -f "${root}/action.yml" ]]; then
  files+=("${root}/action.yml")
fi
if [[ -f "${root}/README.md" ]]; then
  files+=("${root}/README.md")
fi
shopt -s nullglob
for f in "${root}/.github/workflows/"*.yml "${root}/.github/workflows/"*.yaml; do
  files+=("$f")
done
for f in "${root}/docs/"*.md; do
  files+=("$f")
done
shopt -u nullglob

if [[ ${#files[@]} -eq 0 ]]; then
  echo "no action.yml, workflows, README.md, or docs/*.md to check under ${root}" >&2
  exit 1
fi

# owner/name[/subdir]@<40 hex>
sha_pin_re='^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$'
# Docs placeholder until a release tag exists (getting-started / README examples).
placeholder_pin_re='^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*@<full-commit-sha>$'
# docker://host/path:tag@sha256:<hex> (digest form)
docker_digest_re='^docker://.+@sha256:[0-9a-fA-F]+$'

unpinned=0
checked=0
for file in "${files[@]}"; do
  if [[ ! -r "$file" ]]; then
    echo "not readable: $file" >&2
    exit 2
  fi
  rel="${file#"${root}/"}"
  while IFS= read -r line || [[ -n "$line" ]]; do
    trimmed="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$trimmed" || "$trimmed" == \#* ]] && continue
    if [[ "$trimmed" =~ ^-?[[:space:]]*uses:[[:space:]]+([^[:space:]]+) ]]; then
      ref="${BASH_REMATCH[1]}"
      ref="${ref%%#*}"
      checked=$((checked + 1))
      # Local composite/reusable action path.
      if [[ "$ref" == ./* ]]; then
        continue
      fi
      if [[ "$ref" =~ $docker_digest_re ]]; then
        continue
      fi
      if [[ "$ref" =~ $sha_pin_re || "$ref" =~ $placeholder_pin_re ]]; then
        continue
      fi
      echo "unpinned uses: $ref" >&2
      echo "  (from ${rel}: $trimmed)" >&2
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
  echo "every uses: must be pinned to a 40-character commit SHA (e.g. owner/repo@deadbeef… # vX.Y.Z)," >&2
  echo "the docs placeholder owner/repo@<full-commit-sha>, a local ./ path, or docker://…@sha256:<digest>" >&2
  exit 1
fi

echo "ok: ${checked} uses: pin(s) across ${#files[@]} file(s)"
