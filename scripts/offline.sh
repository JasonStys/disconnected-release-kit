#!/usr/bin/env bash
# Jason Stys: disposable CI-only loopback namespace; never alter the developer PC or host routes.
# Function cleanup releases only the owned namespace; variables and workflow parameters are mapped below.
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# shell variable: namespace — line 18
# shell variable: python — line 19
# shell variable: owned — line 20
# shell function: cleanup — line 22
# shell variable: status — line 23
# shell loop/input: process — line 25
# shell variable: owned — line 43
# END CODE MAP
set -euo pipefail
if [[ "${1:-}" != "--run-isolated-demo" || "${GITHUB_ACTIONS:-}" != "true" || "$(uname -s)" != "Linux" || "$(id -u)" != 0 ]]; then
  echo "Explicit disposable GitHub Linux runner opt-in required" >&2
  exit 2
fi
namespace="drk-$BASHPID"
python="${DRKIT_PYTHON:?Trusted preprovisioned Python path required}"
owned=false
# Preserve the original status and terminate only residual processes in our new test namespace.
cleanup() {
  local status=$?
  if [[ "$owned" == true ]]; then
    while read -r process; do
      if [[ -n "$process" ]]; then kill "$process" 2>/dev/null || true; fi
    done < <(ip netns pids "$namespace")
    ip netns delete "$namespace"
    if ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
      echo "Owned namespace cleanup failed" >&2
      exit 1
    fi
    echo '{"author":"Jason Stys","owned_namespace_cleanup":true}'
  fi
  exit "$status"
}
trap cleanup EXIT
if ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
  echo "Namespace name collision; refusing takeover" >&2
  exit 2
fi
ip netns add "$namespace"
owned=true
ip -n "$namespace" link set lo up
ip netns exec "$namespace" "$python" scripts/offline_probe.py --namespace "$namespace"
