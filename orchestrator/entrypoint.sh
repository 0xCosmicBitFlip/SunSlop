#!/bin/sh
# One image. GS_ROLE, set on the pod, chooses which process starts.
# orchestrator: seats and the API. No Moonlight sockets, no relay compile.
# proxy: compile gs-relay, then the Moonlight and Selkies process.
# all: local single process (not used by the deploy). Compiles the relay.
set -eu
# Same spelling load_config accepts: lower case, surrounding space ignored.
role=$(printf '%s' "${GS_ROLE:-all}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
case "$role" in
  orchestrator)
    exec python3 -u /usr/local/bin/orchestrator.py "$@"
    ;;
  proxy)
    /usr/local/bin/relay-build.sh
    exec python3 -u /usr/local/bin/moonlight_proxy.py "$@"
    ;;
  all)
    /usr/local/bin/relay-build.sh
    exec python3 -u /usr/local/bin/orchestrator.py "$@"
    ;;
  *)
    echo "gs-entrypoint: bad GS_ROLE=$role" >&2
    exit 1
    ;;
esac
