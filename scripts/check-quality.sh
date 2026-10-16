#!/usr/bin/env bash
# Verify Go code quality in throwaway Docker containers.
# The host needs Docker and nothing else: no Go toolchain, no golangci-lint.
set -euo pipefail

GOLANGCI_IMAGE="golangci/golangci-lint:v2.14.0@sha256:ad862ba6b3798cbe0fd9fd7408d498fd74fbd2623a92406b2fd3898faf0bf98f"
# Must equal the server release builder image.
GOLANG_IMAGE="golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c"
GOVULN_MODULE="golang.org/x/vuln/cmd/govulncheck@v1.9.0"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export LC_ALL=C

REPO_KEY="$(basename "$ROOT" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_.-]/-/g')"
VOL_BUILD="${REPO_KEY}-go-build"
VOL_MOD="${REPO_KEY}-go-mod"
VOL_LINT="${REPO_KEY}-golangci"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"
COVERAGE_MIN="${COVERAGE_MIN:-0}"

MODULES=()
RESULTS_NAMES=()
RESULTS_STATUS=()
RESULTS_DURATION=()
FAILED=0
MODE_FIX=0
MODE_FAST=0
MODE_ONLY=""
MODE_CLEAN=0
MODE_NEW=0

usage() {
  cat <<EOF
Usage: ./scripts/check-quality.sh [options]

Run Go quality checks in throwaway containers (docker run --rm).
Nothing is installed on the host except Docker.

Options:
  --fix            go mod tidy, golangci-lint fmt, golangci-lint run --fix,
                   then the full verification (unless combined with --only)
  --fix --only fmt Run only golangci-lint fmt (no tidy, no lint --fix)
  --fix --only tidy Run only go mod tidy per module
  --fix --only lint Run only golangci-lint run --fix per module
  --fast           Run only fmt and lint
  --new            Lint only: pass --new-from-merge-base=origin/main to golangci-lint
  --only <check>   Run one check: tidy, fmt, lint, vuln, build, test, coverage
  --clean-cache    Remove the named Docker cache volumes and exit
  --help           Show this help

Environment:
  COVERAGE_MIN     Minimum statement coverage percent (default 0, report only)

Images (pinned):
  ${GOLANGCI_IMAGE}
  ${GOLANG_IMAGE}

Module tags:
  Optional .quality-tags at a module root (one line) is passed as -tags to
  build, test, lint, and vuln for that module.

Coverage:
  go test writes coverage.out at each module root (gitignored via *.out).

Caches (named volumes, reused across runs):
  ${VOL_BUILD}   GOCACHE
  ${VOL_MOD}     GOMODCACHE
  ${VOL_LINT}    GOLANGCI_LINT_CACHE

Note: the vuln check downloads module metadata and needs network inside Docker.
EOF
}

canonical_check() {
  case "$1" in
    tidy) printf 'tidy\n' ;;
    fmt | format | formatting) printf 'fmt\n' ;;
    lint) printf 'lint\n' ;;
    vuln | vulnerability | vulnerabilities) printf 'vuln\n' ;;
    build) printf 'build\n' ;;
    test | tests) printf 'test\n' ;;
    coverage) printf 'coverage\n' ;;
    *) return 1 ;;
  esac
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --fix)
        MODE_FIX=1
        shift
        ;;
      --fast)
        MODE_FAST=1
        shift
        ;;
      --new)
        MODE_NEW=1
        shift
        ;;
      --only)
        if [[ $# -lt 2 ]]; then
          echo "error: --only requires a check name" >&2
          usage >&2
          exit 2
        fi
        MODE_ONLY="$2"
        shift 2
        ;;
      --only=*)
        MODE_ONLY="${1#--only=}"
        shift
        ;;
      --clean-cache)
        MODE_CLEAN=1
        shift
        ;;
      --help | -h)
        usage
        exit 0
        ;;
      *)
        echo "error: unknown argument: $1" >&2
        usage >&2
        exit 2
        ;;
    esac
  done

  if [[ -n "$MODE_ONLY" && "$MODE_FAST" -eq 1 ]]; then
    echo "error: --only and --fast cannot be combined" >&2
    exit 2
  fi
  if [[ -n "$MODE_ONLY" ]]; then
    if ! canonical_check "$MODE_ONLY" >/dev/null; then
      echo "error: unknown check '${MODE_ONLY}'" >&2
      echo "checks: tidy, fmt, lint, vuln, build, test, coverage" >&2
      exit 2
    fi
    MODE_ONLY="$(canonical_check "$MODE_ONLY")"
  fi
  if [[ "$MODE_FIX" -eq 1 && -n "$MODE_ONLY" ]]; then
    case "$MODE_ONLY" in
      tidy | fmt | lint) ;;
      *)
        echo "error: --fix --only supports tidy, fmt, or lint (not '${MODE_ONLY}')" >&2
        exit 2
        ;;
    esac
  fi
}

require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "error: Docker is not installed. Install Docker, then re-run ./scripts/check-quality.sh." >&2
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "error: Docker is not running. Start Docker, then re-run ./scripts/check-quality.sh." >&2
    exit 1
  fi
}

load_modules() {
  local mod rel
  MODULES=()
  while IFS= read -r mod; do
    rel="${mod#"$ROOT"/}"
    rel="$(dirname "$rel")"
    MODULES+=("$rel")
  done < <(find "$ROOT" -name go.mod -not -path '*/vendor/*' -not -path '*/.git/*' | sort)
  if [[ ${#MODULES[@]} -eq 0 ]]; then
    echo "error: no go.mod under ${ROOT}" >&2
    exit 1
  fi
}

module_workdir() {
  if [[ "$1" == "." ]]; then
    printf '/app\n'
  else
    printf '/app/%s\n' "$1"
  fi
}

# Coverage profiles land at <module>/coverage.out on the host (bind-mounted /app).
module_profile() {
  if [[ "$1" == "." ]]; then
    printf '%s/coverage.out\n' "$ROOT"
  else
    printf '%s/%s/coverage.out\n' "$ROOT" "$1"
  fi
}

module_quality_tags() {
  local mod="$1" tags_file line
  if [[ "$mod" == "." ]]; then
    tags_file="${ROOT}/.quality-tags"
  else
    tags_file="${ROOT}/${mod}/.quality-tags"
  fi
  [[ -f "$tags_file" ]] || return 0
  IFS= read -r line < "$tags_file" || true
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  [[ -n "$line" ]] && printf '%s' "$line"
}

prepare_caches() {
  echo "Preparing cache volumes (${VOL_BUILD}, ${VOL_MOD}, ${VOL_LINT})..."
  docker run --rm \
    -v "${VOL_BUILD}:/cache/go-build" \
    -v "${VOL_MOD}:/cache/go-mod" \
    -v "${VOL_LINT}:/cache/golangci" \
    "${GOLANG_IMAGE}" \
    sh -c "mkdir -p /cache/go-build /cache/go-mod/gopath /cache/golangci && chown -R ${HOST_UID}:${HOST_GID} /cache/go-build /cache/go-mod /cache/golangci"
}

clean_caches() {
  local vol
  for vol in "$VOL_BUILD" "$VOL_MOD" "$VOL_LINT"; do
    if docker volume inspect "$vol" >/dev/null 2>&1; then
      docker volume rm "$vol"
    else
      echo "not present: ${vol}"
    fi
  done
  echo "Removed Docker cache volumes for ${REPO_KEY}."
}

# Image, workdir, CGO_ENABLED (empty keeps the image default), then the command.
# The docker invocation is duplicated so an empty CGO value is not expanded
# under `set -u` on macOS bash 3.2.
docker_run() {
  local image="$1"
  local workdir="$2"
  local cgo="$3"
  shift 3
  if [[ -n "$cgo" ]]; then
    docker run --rm \
      --user "${HOST_UID}:${HOST_GID}" \
      -e HOME=/tmp/quality-home \
      -e GOCACHE=/cache/go-build \
      -e GOMODCACHE=/cache/go-mod \
      -e GOPATH=/cache/go-mod/gopath \
      -e GOLANGCI_LINT_CACHE=/cache/golangci \
      -e COVERAGE_MIN="${COVERAGE_MIN}" \
      -e GOWORK=off \
      -e GOTOOLCHAIN=local \
      -e GIT_CONFIG_COUNT=1 \
      -e GIT_CONFIG_KEY_0=safe.directory \
      -e GIT_CONFIG_VALUE_0=/app \
      -e "CGO_ENABLED=${cgo}" \
      -v "${ROOT}:/app" \
      -v "${VOL_BUILD}:/cache/go-build" \
      -v "${VOL_MOD}:/cache/go-mod" \
      -v "${VOL_LINT}:/cache/golangci" \
      -w "$workdir" \
      "$image" \
      sh -c 'mkdir -p "$HOME" "$GOPATH" "$GOCACHE" "$GOMODCACHE" "$GOLANGCI_LINT_CACHE" && exec "$@"' sh "$@"
  else
    docker run --rm \
      --user "${HOST_UID}:${HOST_GID}" \
      -e HOME=/tmp/quality-home \
      -e GOCACHE=/cache/go-build \
      -e GOMODCACHE=/cache/go-mod \
      -e GOPATH=/cache/go-mod/gopath \
      -e GOLANGCI_LINT_CACHE=/cache/golangci \
      -e COVERAGE_MIN="${COVERAGE_MIN}" \
      -e GOWORK=off \
      -e GOTOOLCHAIN=local \
      -e GIT_CONFIG_COUNT=1 \
      -e GIT_CONFIG_KEY_0=safe.directory \
      -e GIT_CONFIG_VALUE_0=/app \
      -v "${ROOT}:/app" \
      -v "${VOL_BUILD}:/cache/go-build" \
      -v "${VOL_MOD}:/cache/go-mod" \
      -v "${VOL_LINT}:/cache/golangci" \
      -w "$workdir" \
      "$image" \
      sh -c 'mkdir -p "$HOME" "$GOPATH" "$GOCACHE" "$GOMODCACHE" "$GOLANGCI_LINT_CACHE" && exec "$@"' sh "$@"
  fi
}

docker_go() {
  local workdir="$1"
  local cgo="$2"
  shift 2
  docker_run "$GOLANG_IMAGE" "$workdir" "$cgo" "$@"
}

docker_lint() {
  local workdir="$1"
  shift
  docker_run "$GOLANGCI_IMAGE" "$workdir" "" "$@"
}

format_duration() {
  local s="$1"
  if ((s >= 60)); then
    printf '%dm%02ds\n' $((s / 60)) $((s % 60))
  else
    printf '%ds\n' "$s"
  fi
}

run_check() {
  local name="$1"
  shift
  local start end status dur
  echo ""
  echo "========== ${name} =========="
  start=$(date +%s)
  set +e
  (
    set -euo pipefail
    "$@"
  )
  status=$?
  set -e
  end=$(date +%s)
  dur=$((end - start))
  RESULTS_NAMES+=("$name")
  RESULTS_DURATION+=("$(format_duration "$dur")")
  if [[ "$status" -eq 0 ]]; then
    RESULTS_STATUS+=("PASS")
    echo "---------- ${name} PASS ----------"
  else
    RESULTS_STATUS+=("FAIL")
    FAILED=1
    echo "---------- ${name} FAIL ----------"
  fi
}

# Continue across modules; return failure if any module failed.
each_module_keep_going() {
  local mod work tags failed=0
  for mod in "${MODULES[@]}"; do
    work="$(module_workdir "$mod")"
    tags="$(module_quality_tags "$mod")"
    if [[ -n "$tags" ]]; then
      echo "---- ${mod} (tags: ${tags}) ----"
    else
      echo "---- ${mod} ----"
    fi
    if ! MODULE="$mod" WORKDIR="$work" "$@"; then
      failed=1
    fi
  done
  return "$failed"
}

tidy_verify_one() {
  # shellcheck disable=SC2016
  docker_go "${WORKDIR:?}" "" sh -c '
    set -eu
    cp go.mod /tmp/quality-go.mod
    had_sum=0
    if [ -f go.sum ]; then
      cp go.sum /tmp/quality-go.sum
      had_sum=1
    fi
    status=0
    go mod tidy || status=$?
    if [ "$status" -eq 0 ]; then
      if ! cmp -s go.mod /tmp/quality-go.mod; then
        echo "go mod tidy would change go.mod"
        diff -u /tmp/quality-go.mod go.mod || true
        status=1
      fi
      if [ "$had_sum" -eq 1 ]; then
        if ! cmp -s go.sum /tmp/quality-go.sum; then
          echo "go mod tidy would change go.sum"
          diff -u /tmp/quality-go.sum go.sum || true
          status=1
        fi
      elif [ -f go.sum ]; then
        echo "go mod tidy would create go.sum"
        diff -u /dev/null go.sum || true
        status=1
      fi
    fi
    cp /tmp/quality-go.mod go.mod
    if [ "$had_sum" -eq 1 ]; then
      cp /tmp/quality-go.sum go.sum
    elif [ -f go.sum ]; then
      rm -f go.sum
    fi
    exit "$status"
  '
}

check_tidy() {
  each_module_keep_going tidy_verify_one
}

fmt_verify_one() {
  local out status=0
  out="$(docker_lint "${WORKDIR:?}" golangci-lint fmt --diff)" || status=$?
  if [[ -n "$out" ]]; then
    printf '%s\n' "$out"
  fi
  if [[ "$status" -ne 0 || -n "$out" ]]; then
    return 1
  fi
}

check_fmt() {
  each_module_keep_going fmt_verify_one
}

lint_one() {
  local tags new_flag=""
  tags="$(module_quality_tags "${MODULE:?}")"
  if [[ "$MODE_NEW" -eq 1 ]]; then
    new_flag="--new-from-merge-base=origin/main"
  fi
  if [[ -n "$tags" ]]; then
    if [[ -n "$new_flag" ]]; then
      docker_lint "${WORKDIR:?}" golangci-lint run "$new_flag" --build-tags="$tags" ./...
    else
      docker_lint "${WORKDIR:?}" golangci-lint run --build-tags="$tags" ./...
    fi
  else
    if [[ -n "$new_flag" ]]; then
      docker_lint "${WORKDIR:?}" golangci-lint run "$new_flag" ./...
    else
      docker_lint "${WORKDIR:?}" golangci-lint run ./...
    fi
  fi
}

check_lint() {
  each_module_keep_going lint_one
}

vuln_one() {
  local tags
  tags="$(module_quality_tags "${MODULE:?}")"
  if [[ -n "$tags" ]]; then
    docker_go "${WORKDIR:?}" "" go run "${GOVULN_MODULE}" -tags="$tags" ./...
  else
    docker_go "${WORKDIR:?}" "" go run "${GOVULN_MODULE}" ./...
  fi
}

check_vuln() {
  each_module_keep_going vuln_one
}

build_one() {
  local tags
  tags="$(module_quality_tags "${MODULE:?}")"
  if [[ -n "$tags" ]]; then
    docker_go "${WORKDIR:?}" "" go build -tags="$tags" ./...
  else
    docker_go "${WORKDIR:?}" "" go build ./...
  fi
}

check_build() {
  each_module_keep_going build_one
}

test_one() {
  local tags mod="${MODULE:?}"
  tags="$(module_quality_tags "$mod")"
  rm -f "$(module_profile "$mod")"
  if [[ -n "$tags" ]]; then
    docker_go "${WORKDIR:?}" 1 go test -race -tags="$tags" -coverprofile=coverage.out ./...
  else
    docker_go "${WORKDIR:?}" 1 go test -race -coverprofile=coverage.out ./...
  fi
}

check_test() {
  each_module_keep_going test_one
}

coverage_one() {
  local profile line pct out status=0 mod="${MODULE:?}"
  profile="$(module_profile "$mod")"
  if [[ ! -f "$profile" ]]; then
    echo "coverage profile missing: ${profile#"$ROOT"/}" >&2
    return 1
  fi
  out="$(docker_go "${WORKDIR:?}" "" go tool cover -func=coverage.out)" || status=$?
  if [[ "$status" -ne 0 ]]; then
    if [[ -n "$out" ]]; then
      printf '%s\n' "$out" >&2
    fi
    return 1
  fi
  line="$(printf '%s\n' "$out" | tail -n 1)"
  printf '%s\n' "$line"
  pct="$(printf '%s\n' "$line" | awk '{ gsub(/%/, "", $NF); print $NF }')"
  if [[ -z "$pct" ]]; then
    echo "could not parse coverage for ${mod}" >&2
    return 1
  fi
  if ! awk -v pct="$pct" -v min="$COVERAGE_MIN" 'BEGIN { exit (pct+0 < min+0) ? 1 : 0 }'; then
    echo "coverage ${pct}% is below COVERAGE_MIN=${COVERAGE_MIN}" >&2
    return 1
  fi
}

print_combined_coverage() {
  local profiles=() mod profile
  for mod in "${MODULES[@]}"; do
    profile="$(module_profile "$mod")"
    if [[ -f "$profile" ]]; then
      profiles+=("$profile")
    fi
  done
  if [[ ${#profiles[@]} -eq 0 ]]; then
    return 0
  fi
  awk '
    BEGIN { total = 0; covered = 0 }
    NF >= 3 && $2 ~ /^[0-9]+$/ {
      total += $2
      if ($3 + 0 > 0) covered += $2
    }
    END {
      if (total == 0) pct = 0
      else pct = 100 * covered / total
      printf "total (all modules): %.1f%% (%d/%d statements)\n", pct, covered, total
    }
  ' "${profiles[@]}"
}

check_coverage() {
  local failed=0
  if ! each_module_keep_going coverage_one; then
    failed=1
  fi
  if [[ ${#MODULES[@]} -gt 1 ]]; then
    print_combined_coverage
  fi
  return "$failed"
}

fix_tidy_one() {
  docker_go "${WORKDIR:?}" "" go mod tidy
}

fix_fmt_one() {
  docker_lint "${WORKDIR:?}" golangci-lint fmt
}

fix_lint_one() {
  local rc=0 tags
  tags="$(module_quality_tags "${MODULE:?}")"
  if [[ -n "$tags" ]]; then
    docker_lint "${WORKDIR:?}" golangci-lint run --build-tags="$tags" --fix ./... || rc=$?
  else
    docker_lint "${WORKDIR:?}" golangci-lint run --fix ./... || rc=$?
  fi
  if [[ "$rc" -gt 1 ]]; then
    return 1
  fi
  if [[ "$rc" -eq 1 ]]; then
    echo "note: golangci-lint run --fix left issues; the lint check reports them"
  fi
  return 0
}

fix_one() {
  local failed=0
  if ! fix_tidy_one; then
    failed=1
  fi
  if ! fix_fmt_one; then
    failed=1
  fi
  if ! fix_lint_one; then
    failed=1
  fi
  return "$failed"
}

apply_fixes() {
  if [[ -n "$MODE_ONLY" ]]; then
    case "$MODE_ONLY" in
      tidy) each_module_keep_going fix_tidy_one ;;
      fmt) each_module_keep_going fix_fmt_one ;;
      lint) each_module_keep_going fix_lint_one ;;
    esac
    return
  fi
  each_module_keep_going fix_one
}

print_summary() {
  local i
  echo ""
  printf '%-16s %-8s %s\n' "check" "result" "duration"
  printf '%-16s %-8s %s\n' "-----" "------" "--------"
  for i in "${!RESULTS_NAMES[@]}"; do
    printf '%-16s %-8s %s\n' "${RESULTS_NAMES[$i]}" "${RESULTS_STATUS[$i]}" "${RESULTS_DURATION[$i]}"
  done
}

want_check() {
  local name="$1"
  if [[ -n "$MODE_ONLY" ]]; then
    [[ "$MODE_ONLY" == "$name" ]]
    return
  fi
  if [[ "$MODE_FAST" -eq 1 ]]; then
    [[ "$name" == "fmt" || "$name" == "lint" ]]
    return
  fi
  return 0
}

main() {
  parse_args "$@"
  if ! [[ "$COVERAGE_MIN" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "error: COVERAGE_MIN must be a number (got '${COVERAGE_MIN}')" >&2
    exit 2
  fi
  require_docker
  load_modules
  if [[ "$MODE_CLEAN" -eq 1 ]]; then
    clean_caches
    exit 0
  fi

  echo "repo: ${ROOT}"
  echo "golangci-lint: ${GOLANGCI_IMAGE}"
  echo "go: ${GOLANG_IMAGE}"
  echo "govulncheck: ${GOVULN_MODULE}"
  echo "modules: ${MODULES[*]}"
  echo "coverage minimum: ${COVERAGE_MIN}"
  if [[ "$MODE_NEW" -eq 1 ]]; then
    echo "lint: --new-from-merge-base=origin/main"
  fi

  prepare_caches

  if [[ "$MODE_FIX" -eq 1 ]]; then
    run_check fix apply_fixes
    if [[ -n "$MODE_ONLY" ]]; then
      print_summary
      exit "$FAILED"
    fi
  fi

  local name
  for name in tidy fmt lint vuln build test coverage; do
    if want_check "$name"; then
      run_check "$name" "check_${name}"
    fi
  done

  print_summary
  if [[ "$FAILED" -ne 0 ]]; then
    exit 1
  fi
}

main "$@"
