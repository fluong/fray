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
if [[ "${FRAY_SHOW_PAYLOAD:-false}" == "true" ]]; then
  args+=(-payload-out "${FRAY_OUT}/payload.json")
fi
case "${FRAY_FAIL_ON_UNENROLLED:-false}" in
  true|True|TRUE|1|yes|YES)
    args+=(-fail-on-unenrolled)
    ;;
esac
if [[ -n "$base_commit" ]]; then
  args+=(-base-commit "$base_commit")
  # Materialize the base-commit sources so Fray can compare module call
  # arguments (never guess which input changed from the inner resource).
  if ! git -C "$root" cat-file -e "${base_commit}^{commit}" 2>/dev/null; then
    echo "Fetching base commit ${base_commit}"
    git -C "$root" fetch --no-tags --depth=1 origin "$base_commit"
  fi
  base_src="${FRAY_OUT}/base-source"
  rm -rf "$base_src"
  mkdir -p "$base_src"
  git -C "$root" archive "$base_commit" "$FRAY_WORKDIR" | tar -x -C "$base_src"
  args+=(-base-source "${base_src}/${FRAY_WORKDIR}")
fi

echo "::group::fray scan"
set +e
"$FRAY_BIN" "${args[@]}"
rc=$?
set -e
echo "::endgroup::"

# Exit codes from fray (cmd/fray), decided with ${FRAY_OUT}/enrollment.json:
#   0 + marker(failed=false)       → skipped (enrollment soft-skip)
#   0 + no marker + findings.sarif → success
#   0 + no marker + no SARIF       → error
#   1 + marker(failed=true)        → fail-on-unenrolled (exit 1)
#   1 + no marker + findings.sarif → gate blocked
#   1 + no marker + no SARIF       → error
#   0/1 + bad marker / mismatch    → error
#   >=2                            → propagate
skipped=false
skip_reason=""
blocked=false
marker="${FRAY_OUT}/enrollment.json"
has_marker=false
marker_code=""
marker_failed=""

if [[ -f "$marker" ]]; then
  if ! parsed="$(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(2)
code = d.get("code")
failed = d.get("failed")
if not isinstance(code, str) or not isinstance(failed, bool):
    sys.exit(2)
print(code)
print("true" if failed else "false")
' "$marker")"; then
    echo "::error::invalid enrollment.json"
    exit 1
  fi
  has_marker=true
  marker_code="$(printf '%s\n' "$parsed" | sed -n '1p')"
  marker_failed="$(printf '%s\n' "$parsed" | sed -n '2p')"
fi

known_enrollment_code() {
  case "$1" in
    installation_inactive|repo_not_enrolled|installation_over_cap) return 0 ;;
    *) return 1 ;;
  esac
}

case "$rc" in
  0|1)
    if [[ "$has_marker" == "true" ]]; then
      if ! known_enrollment_code "$marker_code"; then
        echo "::error::invalid enrollment marker code"
        exit 1
      fi
      if [[ "$rc" -eq 0 ]]; then
        if [[ "$marker_failed" != "false" ]]; then
          echo "::error::enrollment marker/rc mismatch"
          exit 1
        fi
        skipped=true
        skip_reason="$marker_code"
      else
        if [[ "$marker_failed" != "true" ]]; then
          echo "::error::enrollment marker/rc mismatch"
          exit 1
        fi
        exit 1
      fi
    elif [[ "$rc" -eq 0 ]]; then
      if [[ -f "${FRAY_OUT}/findings.sarif" ]]; then
        :
      else
        echo "::error::fray exited 0 without results"
        exit 1
      fi
    else
      if [[ -f "${FRAY_OUT}/findings.sarif" ]]; then
        blocked=true
      else
        echo "::error::fray exited 1 without findings.sarif"
        exit 1
      fi
    fi
    ;;
  *)
    echo "::error::fray exited with status ${rc}"
    exit "$rc"
    ;;
esac

{
  echo "skipped=${skipped}"
  echo "skip_reason=${skip_reason}"
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
  if [[ -f "${FRAY_OUT}/payload.json" ]]; then
    echo "has_payload=true"
  else
    echo "has_payload=false"
  fi
} >> "$GITHUB_OUTPUT"

if [[ "$skipped" == "true" ]]; then
  echo "Fray scan skipped (enrollment: ${skip_reason})"
else
  echo "Fray scan complete (blocked=${blocked})"
fi
