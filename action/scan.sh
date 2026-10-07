#!/usr/bin/env bash
# Plan the Terraform root, scan with Fray, write artifacts under FRAY_OUT.
set -euo pipefail

# Accepted truthy set for Action inputs (same as fail-on-unenrolled historically):
# true|True|TRUE|1|yes|YES
is_true() {
  case "${1:-false}" in
    true|True|TRUE|1|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

# Escape untrusted text for GitHub Actions workflow-command properties
# (same rules as cmd/fray escapeWorkflowCommand).
escape_workflow_command() {
  local s=$1
  s=${s//%/%25}
  s=${s//$'\r'/%0D}
  s=${s//$'\n'/%0A}
  printf '%s' "$s"
}

# Mirror cmd/fray sanitizeSummaryText (enrollment v0.5.5): collapse newlines, HTML-escape.
sanitize_summary_text() {
  python3 -c 'import html,sys
s=sys.argv[1].replace("\r\n","\n").replace("\r","\n").replace("\n"," ")
print(html.escape(s))' "$1"
}

# Handle a rate_limited marker: warn (default) or fail when fail-on-rate-limit.
# Args: message retry_after. Uses FRAY_FAIL_ON_RATE_LIMIT, GITHUB_STEP_SUMMARY.
handle_rate_limited_marker() {
  local message=$1
  local retry_after=$2
  local notice
  notice="$(escape_workflow_command "${message} (retry after ${retry_after} s)")"
  local summary
  summary="$(sanitize_summary_text "${message} (retry after ${retry_after} s)")"

  if is_true "${FRAY_FAIL_ON_RATE_LIMIT:-false}"; then
    echo "::error::${notice}"
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
      {
        echo "## Fray"
        echo ""
        echo "${summary}"
      } >>"$GITHUB_STEP_SUMMARY"
    fi
    return 1
  fi
  echo "::warning::${notice}"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "## Fray"
      echo ""
      echo "${summary}"
    } >>"$GITHUB_STEP_SUMMARY"
  fi
  return 0
}

# Parse ${FRAY_OUT}/enrollment.json into marker_* globals. Exit 1 on invalid.
parse_enrollment_marker_file() {
  local marker=$1
  local parsed
  if ! parsed="$(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(2)
if d.get("status") == "rate_limited":
    msg = d.get("message")
    ra = d.get("retry_after")
    if not isinstance(msg, str):
        sys.exit(2)
    if not (isinstance(ra, int) and not isinstance(ra, bool) and ra >= 1):
        sys.exit(2)
    msg = msg.replace("\r", " ").replace("\n", " ")
    if len(msg) > 500:
        msg = msg[:500]
    # Stable lines: kind, retry_after, message (message last so newlines cannot shift fields).
    print("rate_limited")
    print(ra)
    print(msg)
    sys.exit(0)
code = d.get("code")
failed = d.get("failed")
if not isinstance(code, str) or not isinstance(failed, bool):
    sys.exit(2)
print("enrollment")
print(code)
print("true" if failed else "false")
' "$marker")"; then
    echo "::error::invalid enrollment.json"
    return 1
  fi
  marker_kind="$(printf '%s\n' "$parsed" | sed -n '1p')"
  if [[ "$marker_kind" == "rate_limited" ]]; then
    marker_rl_retry="$(printf '%s\n' "$parsed" | sed -n '2p')"
    marker_rl_message="$(printf '%s\n' "$parsed" | sed -n '3p')"
    if [[ ! "$marker_rl_retry" =~ ^[1-9][0-9]*$ ]]; then
      echo "::error::invalid rate_limited marker"
      return 1
    fi
  else
    marker_code="$(printf '%s\n' "$parsed" | sed -n '2p')"
    marker_failed="$(printf '%s\n' "$parsed" | sed -n '3p')"
  fi
  return 0
}

# Self-test entrypoints for Go harness (no Terraform / fray binary required).
case "${1:-}" in
  --self-test-rate-limit)
    handle_rate_limited_marker "${2:?message}" "${3:?retry_after}"
    exit $?
    ;;
  --self-test-parse-marker)
    marker_kind=""
    marker_code=""
    marker_failed=""
    marker_rl_message=""
    marker_rl_retry=""
    parse_enrollment_marker_file "${2:?marker}"
    if [[ "$marker_kind" == "rate_limited" ]]; then
      handle_rate_limited_marker "$marker_rl_message" "$marker_rl_retry"
      exit $?
    fi
    printf 'kind=%s code=%s failed=%s\n' "$marker_kind" "$marker_code" "$marker_failed"
    exit 0
    ;;
  --self-test-clear-stale-marker)
    : "${FRAY_OUT:?}"
    rm -f "${FRAY_OUT}/enrollment.json"
    exit 0
    ;;
esac

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
if is_true "${FRAY_SHOW_PAYLOAD:-false}"; then
  args+=(-payload-out "${FRAY_OUT}/payload.json")
fi
if is_true "${FRAY_FAIL_ON_UNENROLLED:-false}"; then
  args+=(-fail-on-unenrolled)
fi
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

# Drop a leftover marker from a previous attempt in the same FRAY_OUT.
rm -f "${FRAY_OUT}/enrollment.json"

echo "::group::fray scan"
set +e
"$FRAY_BIN" "${args[@]}"
rc=$?
set -e
echo "::endgroup::"

# Exit codes from fray (cmd/fray), decided with ${FRAY_OUT}/enrollment.json:
#   0 + marker(status=rate_limited) → rate-limit soft-skip (warn) or fail-on-rate-limit
#   0 + marker(failed=false)        → skipped (enrollment soft-skip)
#   0 + no marker + findings.sarif  → success
#   0 + no marker + no SARIF        → error
#   1 + marker(failed=true)         → fail-on-unenrolled (exit 1)
#   1 + no marker + findings.sarif  → gate blocked
#   1 + no marker + no SARIF        → error
#   0/1 + bad marker / mismatch     → error
#   >=2                             → propagate
#
# fail-on-unenrolled and fail-on-rate-limit are independent.
skipped=false
skip_reason=""
blocked=false
marker="${FRAY_OUT}/enrollment.json"
has_marker=false
marker_kind="" # enrollment | rate_limited
marker_code=""
marker_failed=""
marker_rl_message=""
marker_rl_retry=""

if [[ -f "$marker" ]]; then
  parse_enrollment_marker_file "$marker" || exit 1
  has_marker=true
fi

known_enrollment_code() {
  case "$1" in
    installation_inactive|repo_not_enrolled|installation_over_cap) return 0 ;;
    *) return 1 ;;
  esac
}

case "$rc" in
  0|1)
    if [[ "$has_marker" == "true" && "$marker_kind" == "rate_limited" ]]; then
      if [[ "$rc" -ne 0 ]]; then
        echo "::error::rate_limited marker/rc mismatch"
        exit 1
      fi
      if ! handle_rate_limited_marker "$marker_rl_message" "$marker_rl_retry"; then
        exit 1
      fi
      skipped=true
      skip_reason="rate_limited"
    elif [[ "$has_marker" == "true" ]]; then
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
  if [[ "$skip_reason" == "rate_limited" ]]; then
    echo "Fray scan skipped (rate_limited)"
  else
    echo "Fray scan skipped (enrollment: ${skip_reason})"
  fi
else
  echo "Fray scan complete (blocked=${blocked})"
fi
