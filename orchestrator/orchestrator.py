#!/usr/bin/env python3
"""On-demand seats, split from the public proxy.

GS_ROLE=proxy is a DaemonSet on each GPU node (hostNetwork). It is the only
thing listening for Moonlight and for the Selkies browser. It asks the
orchestrator to create a seat and only splices when that seat is on this
same node. A seat on another node is not spliced: Moonlight is given that
node's address in serverinfo and then reset so its next poll lands there,
and the browser is redirected. HTTP_FOREIGN=reset skips the hand-off.

GS_ROLE=orchestrator is one pod with no GPU and no host network. It creates
and deletes seats. The shared proxy certificate is generated on first start
under the persist volume; every proxy uses it, and the seat boot script
installs the public half into Sunshine.

GS_ROLE=all is the older single process, for a local run. The deploy does
not use it.

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
from gs.seats import RemoteSeats, Seats


def main():
    if "--self-test" in sys.argv:
        from gs.orchtest import self_test
        self_test()
        return 0
    cfg = load_config()
    require_persist_mount(cfg.persist_mount)
    directory = Directory(cfg.users_file, reserved_names(cfg.common_dir, cfg.layer_dir, cfg.proxy_dir))
    if cfg.role == "proxy":
        publish_proxy_cert(cfg)
        App(cfg, directory, RemoteSeats(cfg)).serve()
        return 0
    publish_proxy_cert(cfg)
    kube = Kube(cfg.namespace, cfg.seat_label)
    cfg.namespace = kube.ns
    seats = Seats(cfg, directory, kube)
    if cfg.role == "orchestrator":
        OrchestratorApi(cfg, directory, seats).serve()
        return 0
    App(cfg, directory, seats).serve()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
