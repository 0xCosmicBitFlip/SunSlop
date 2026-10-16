#!/usr/bin/env python3
"""Moonlight and Selkies proxy.

This is the process the image starts when GS_ROLE=proxy. The orchestrator
is the other process in the same image (GS_ROLE=orchestrator). Pairing,
TLS, the Selkies reverse proxy, and /admin stay in the gs package. This
file only loads them.

With no GS_ROLE, or with --self-test, this runs the Moonlight self-test
instead of listening. That is how `python3 orchestrator/moonlight_proxy.py`
is invoked from a checkout.
"""

import os
import sys

from gs.moonlight import MoonlightProxy
from gs.store import Store


def self_test():
    from gs.moontest import self_test as run
    run()


def serve():
    from gs.api import publish_proxy_cert
    from gs.browser import App
    from gs.config import load_config, require_persist_mount
    from gs.model import Directory, reserved_names
    from gs.seats import RemoteSeats

    cfg = load_config()
    if cfg.role != "proxy":
        raise SystemExit(f"moonlight_proxy serves GS_ROLE=proxy, not {cfg.role}")
    require_persist_mount(cfg.persist_mount)
    directory = Directory(
        cfg.users_file, reserved_names(cfg.common_dir, cfg.layer_dir, cfg.proxy_dir)
    )
    publish_proxy_cert(cfg)
    App(cfg, directory, RemoteSeats(cfg)).serve()


def main():
    role = os.environ.get("GS_ROLE", "").strip().lower()
    if "--self-test" in sys.argv or role != "proxy":
        self_test()
        return 0
    serve()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
