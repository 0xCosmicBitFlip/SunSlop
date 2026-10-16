#!/usr/bin/env python3
"""Moonlight-facing proxy.

Clients pair with this process, not with a seat. Moonlight's four pairing
phases are plain HTTP on the configured Sunshine base. The follow-up
pairchallenge, and every later control call, is TLS on the HTTPS port. The
client certificate selects a login. If the seat is down the request is held
until it is up, then a second TLS session to the pod presents the shared
proxy certificate.

The pieces live next to this file: gs.protocol (codec), gs.pairing (the four
phases), gs.store (the shared certificate), gs.relay (UDP/RTSP control), and
gs.moonlight (TLS, the HTTP port, and /admin).
"""

from gs.moonlight import MoonlightProxy
from gs.store import Store


def self_test():
    from gs.moontest import self_test as run
    run()


if __name__ == "__main__":
    self_test()
