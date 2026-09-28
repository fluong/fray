#!/usr/bin/env bash
# Plan the Terraform root, scan with Fray, write artifacts under FRAY_OUT.
set -euo pipefail

: "${FRAY_BIN:?}"
: "${FRAY_API_URL:?}"
: "${FRAY_OIDC_TOKEN:?}"
: "${FRAY_WORKDIR:?}"
: "${FRAY_CONFIG:?}"
: "${FRAY_OUT:?}"

root="${GITHUB_WORKSPACE:?}"
workdir="${root}/${FRAY_WORKDIR}"
config="${root}/${FRAY_CONFIG}"
mitigations="${root}/mitigations.yaml"

if [[ ! -d "$workdir" ]]; then
  echo "::error::working-directory not found: ${FRAY_WORKDIR}"
  exit 2
fi
if [[ ! -f "$config" ]]; then
  echo "::error::fray.yaml not found: ${FRAY_CONFIG}"
  exit 2
fi
if [[ ! -f "$mitigations" ]]; then
  # Empty dispositions file — CLI still requires the path.
  cat >"$mitigations" <<'YAML'
schema_version: mitigation/v1
entries: []
YAML
fi

mkdir -p "$FRAY_OUT"
plan_bin="${FRAY_OUT}/tfplan"
plan_json="${FRAY_OUT}/plan.json"

echo "::group::terraform init"
terraform -chdir="$workdir" init -input=false -no-color
echo "::endgroup::"

echo "::group::terraform plan"
terraform -chdir="$workdir" plan -input=false -no-color -out="$plan_bin"
echo "::endgroup::"

terraform -chdir="$workdir" show -json "$plan_bin" >"$plan_json"

repo="${GITHUB_REPOSITORY}"
sha="${GITHUB_SHA}"
default_branch="${GITHUB_BASE_REF:-}"
branch="${GITHUB_REF_NAME:-}"
base_commit=""

case "${GITHUB_EVENT_NAME}" in
  pull_request)
    sha="${GITHUB_EVENT_PULL_REQUEST_HEAD_SHA:-$GITHUB_SHA}"
    # Prefer event payload when available.
    if [[ -n "${GITHUB_EVENT_PATH:-}" ]]; then
      sha="$(python3 -c 'import json,os; e=json.load(open(os.environ["GITHUB_EVENT_PATH"])); print(e["pull_request"]["head"]["sha"])')"
      base_commit="$(python3 -c 'import json,os; e=json.load(open(os.environ["GITHUB_EVENT_PATH"])); print(e["pull_request"]["base"]["sha"])')"
      branch="$(python3 -c 'import json,os; e=json.load(open(os.environ["GITHUB_EVENT_PATH"])); print(e["pull_request"]["head"]["ref"])')"
      default_branch="$(python3 -c 'import json,os; e=json.load(open(os.environ["GITHUB_EVENT_PATH"])); print(e["pull_request"]["base"]["ref"])')"
    fi
    ;;
  push)
    branch="${GITHUB_REF_NAME}"
    default_branch="$(python3 -c 'import json,os; e=json.load(open(os.environ["GITHUB_EVENT_PATH"])); print(e.get("repository",{}).get("default_branch","main"))' 2>/dev/null || echo main)"
    if [[ "${GITHUB_REF}" == "refs/heads/${default_branch}" ]]; then
      branch="$default_branch"
    fi
    ;;
  *)
    default_branch="${default_branch:-main}"
    branch="${branch:-$default_branch}"
    ;;
esac

if [[ -z "$default_branch" ]]; then
  default_branch=main
fi

args=(
  -plan "$plan_json"
  -source "$workdir"
  -config "$config"
  -mitigations "$mitigations"
  -remote "$FRAY_API_URL"
  -repo "$repo"
  -commit "$sha"
  -branch "$branch"
  -default-branch "$default_branch"
  -out "$FRAY_OUT"
  -oidc-token "$FRAY_OIDC_TOKEN"
)
if [[ -n "$base_commit" ]]; then
  args+=(-base-commit "$base_commit")
fi

echo "::group::fray scan"
set +e
"$FRAY_BIN" "${args[@]}"
rc=$?
set -e
echo "::endgroup::"

blocked=false
case "$rc" in
  0) blocked=false ;;
  1) blocked=true ;;
  *)
    echo "::error::fray exited with status ${rc}"
    exit "$rc"
    ;;
esac

{
  echo "blocked=${blocked}"
  echo "out=${FRAY_OUT}"
  if [[ -f "${FRAY_OUT}/pr-comment.md" ]]; then
    echo "has_comment=true"
  else
    echo "has_comment=false"
  fi
  if [[ -f "${FRAY_OUT}/findings.sarif" ]]; then
    echo "has_sarif=true"
  else
    echo "has_sarif=false"
  fi
} >> "$GITHUB_OUTPUT"

echo "Fray scan complete (blocked=${blocked})"
