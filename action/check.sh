#!/usr/bin/env bash
# Setup checks only: no scan submit, no SARIF/PR/gate.
set -euo pipefail

: "${FRAY_BIN:?}"
: "${FRAY_API_URL:?}"
: "${FRAY_WORKDIR:?}"
: "${FRAY_CONFIG:?}"
: "${FRAY_OUT:?}"

FRAY_TROUBLESHOOT_URL="https://github.com/fluong/fray#troubleshooting"

root="${GITHUB_WORKSPACE:?}"
workdir="${root}/${FRAY_WORKDIR}"
config="${root}/${FRAY_CONFIG}"
waivers="${root}/${FRAY_WAIVERS_FILE:-.fray/waivers.yml}"
mitigations="${root}/mitigations.yaml"

mkdir -p "$FRAY_OUT"

args=(
  -check
  -source "$workdir"
  -config "$config"
  -waivers "$waivers"
  -remote "$FRAY_API_URL"
)

if [[ -f "$mitigations" ]]; then
  args+=(-mitigations "$mitigations")
fi

if [[ -n "${FRAY_PLAN_FILE:-}" ]]; then
  set +e
  resolved_plan="$(python3 -c '
import os, sys
root = os.path.realpath(sys.argv[1])
workdir = os.path.realpath(sys.argv[2])
rel = sys.argv[3]
if not rel or os.path.isabs(rel):
    sys.exit(10)
parts = [p for p in rel.replace("\\", "/").split("/") if p not in ("", ".")]
if any(p == ".." for p in parts):
    sys.exit(11)
if not (workdir == root or workdir.startswith(root + os.sep)):
    sys.exit(12)
candidate = os.path.join(workdir, *parts)
if not os.path.lexists(candidate):
    sys.exit(13)
resolved = os.path.realpath(candidate)
if not (resolved == root or resolved.startswith(root + os.sep)):
    sys.exit(14)
if not os.path.isfile(resolved):
    sys.exit(13)
print(resolved)
' "$root" "$workdir" "$FRAY_PLAN_FILE")"
  plan_rc=$?
  set -e
  if [[ "$plan_rc" -ne 0 ]]; then
    case "$plan_rc" in
      10|11|12|14)
        echo "::error::plan-file path must stay under the GitHub workspace (no absolute paths outside, no .. escapes, no outbound symlinks). See ${FRAY_TROUBLESHOOT_URL}."
        ;;
      *)
        echo "::error::plan-file not found: ${FRAY_WORKDIR}/${FRAY_PLAN_FILE}. Pass a terraform show -json file relative to working-directory. See ${FRAY_TROUBLESHOOT_URL}."
        ;;
    esac
    exit 2
  fi
  args+=(-plan "$resolved_plan" -external-plan)
fi

echo "::group::fray setup check"
set +e
"$FRAY_BIN" "${args[@]}"
rc=$?
set -e
echo "::endgroup::"

{
  echo "skipped=true"
  echo "skip_reason=setup_check"
  echo "blocked=false"
  echo "out=${FRAY_OUT}"
  echo "has_comment=false"
  echo "has_sarif=false"
  echo "sarif_file="
  echo "has_payload=false"
} >>"${GITHUB_OUTPUT:-/dev/null}"

exit "$rc"
