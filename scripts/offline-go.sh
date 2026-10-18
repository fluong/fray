#!/usr/bin/env bash
# Run go with offline module policy (B-76): no module downloads.
set -euo pipefail

export GOPROXY=off

if [[ -n "${GOFLAGS:-}" ]]; then
  case " ${GOFLAGS} " in
    *" -mod=readonly "*) ;;
    *) export GOFLAGS="${GOFLAGS} -mod=readonly" ;;
  esac
else
  export GOFLAGS=-mod=readonly
fi

if ! go "$@"; then
  status=$?
  echo "offline-go: go failed (GOPROXY=off). If the error is a missing module, populate the module cache elsewhere — do not download modules in this wrapper." >&2
  exit "$status"
fi
