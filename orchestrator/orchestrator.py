#!/usr/bin/env python3
"""On-demand seats.

The image is shared with the proxy. The container entrypoint reads GS_ROLE
and starts this file only for the orchestrator (and for GS_ROLE=all, a
local process that is not what the manifests deploy).

GS_ROLE=orchestrator creates and deletes seats. It does not listen for
Moonlight. The shared proxy certificate is generated here on first start
when no proxy has written it yet.

GS_ROLE=proxy is moonlight_proxy.py. Starting it from this file is refused
so a pod cannot accidentally open the public ports and the API together.

GS_ROLE=all is the older single process, for a local run.

The implementation is the gs package next to this file: users and cookies
in gs.model, seat pods in gs.seats, the browser proxy in gs.browser, and
the proxy API in gs.api.
"""

import sys

from gs.api import OrchestratorApi, publish_proxy_cert
from gs.browser import App
from gs.config import load_config, require_persist_mount
from gs.kube import Kube
from gs.model import Directory, reserved_names
from gs.seats import Seats


def main():
    if "--self-test" in sys.argv:
        from gs.orchtest import self_test
        self_test()
        return 0
    cfg = load_config()
    if cfg.role == "proxy":
        raise SystemExit(
            "GS_ROLE=proxy is /usr/local/bin/moonlight_proxy.py. "
            "The image entrypoint starts that process."
        )
    require_persist_mount(cfg.persist_mount)
    directory = Directory(cfg.users_file, reserved_names(cfg.common_dir, cfg.layer_dir, cfg.proxy_dir))
    publish_proxy_cert(cfg)
    kube = Kube(cfg.namespace, cfg.seat_label)
    cfg.namespace = kube.ns
    seats = Seats(cfg, directory, kube)
    if cfg.role == "orchestrator":
        from gs.board import SeatBoard
        from gs.cache import CacheClient
        seats.board = SeatBoard(
            cfg.instance, CacheClient(cfg.cache_url),
            stale=cfg.orch_stale, grace=cfg.claim_grace, idle=cfg.idle_seconds,
        )
        OrchestratorApi(cfg, directory, seats).serve()
        return 0
    App(cfg, directory, seats).serve()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
