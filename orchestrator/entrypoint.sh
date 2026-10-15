#!/bin/sh
# Proxy pods compile the UDP/RTSP relay before Python listens. The
# orchestrator does not own those sockets.
set -eu
role="${GS_ROLE:-all}"
case "$role" in
  proxy|all)
    /usr/local/bin/relay-build.sh
    ;;
esac
exec python3 -u /usr/local/bin/orchestrator.py "$@"
