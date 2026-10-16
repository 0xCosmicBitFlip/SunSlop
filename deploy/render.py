#!/usr/bin/env python3
"""Copy deploy/gs-config.yaml into the other manifests and print them.

Edit that ConfigMap, then:

    python3 deploy/render.py | kubectl apply -f -

Derived keys (not stored in the ConfigMap): USER_BASE_0..7 are
SUNSHINE_BASE + n*USER_PORT_STRIDE, and SUNSHINE_HTTPS_PORT / WEB / RTSP /
UDP_PORTS are the base plus the offsets. An explicit key in the ConfigMap
wins.

--time-slicing adds the GPU Operator ConfigMap.
--seat adds the one-pod debug manifest. Do not apply it for a user the
orchestrator is also serving.
"""

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
KEY = re.compile(r"^([A-Z0-9_]+):\s*(?:\"([^\"]*)\"|'([^']*)'|(\S+))\s*$")
PLACE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def load_config(path):
    text = path.read_text()
    data = {}
    in_data = False
    for raw in text.splitlines():
        if raw.startswith("data:"):
            in_data = True
            continue
        if not in_data:
            continue
        if raw and not raw.startswith((" ", "\t")):
            break
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = KEY.match(line)
        if not match:
            raise SystemExit(f"{path}: cannot parse {raw!r}")
        value = next(group for group in match.groups()[1:] if group is not None)
        data[match.group(1)] = value
    if "NAMESPACE" not in data or "PERSIST_ROOT" not in data:
        raise SystemExit(f"{path}: missing NAMESPACE or PERSIST_ROOT")
    return data


def _num(values, key):
    try:
        return int(str(values[key]).strip())
    except (KeyError, ValueError) as exc:
        raise SystemExit(f"gs-config: {key} must be an integer") from exc


def derive(values):
    base = _num(values, "SUNSHINE_BASE")
    stride = _num(values, "USER_PORT_STRIDE") if "USER_PORT_STRIDE" in values else 100
    https = _num(values, "SUNSHINE_HTTPS_OFFSET") if "SUNSHINE_HTTPS_OFFSET" in values else -5
    web = _num(values, "SUNSHINE_WEB_OFFSET") if "SUNSHINE_WEB_OFFSET" in values else 1
    rtsp = _num(values, "SUNSHINE_RTSP_OFFSET") if "SUNSHINE_RTSP_OFFSET" in values else 21
    raw_offs = values.get("SUNSHINE_UDP_OFFSETS", "9,10,11,13,21")
    offs = []
    for part in str(raw_offs).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            offs.append(int(part))
        except ValueError as exc:
            raise SystemExit("gs-config: SUNSHINE_UDP_OFFSETS must be integers") from exc
    values.setdefault("SUNSHINE_HTTPS_PORT", str(base + https))
    values.setdefault("SUNSHINE_WEB_PORT", str(base + web))
    values.setdefault("SUNSHINE_RTSP_PORT", str(base + rtsp))
    values.setdefault("SUNSHINE_UDP_PORTS", ",".join(str(base + off) for off in offs))
    for i in range(8):
        values.setdefault(f"USER_BASE_{i}", str(base + i * stride))
    ready = _num(values, "READY_TIMEOUT") if "READY_TIMEOUT" in values else 900
    period = 2
    ready = max(ready, period)
    values.setdefault("SEAT_PROBE_FAILURES", str(max(1, (ready + period - 1) // period)))
    return values


def fill(text, values, path):
    missing = sorted(set(PLACE.findall(text)) - set(values))
    if missing:
        raise SystemExit(f"{path}: no value for {', '.join(missing)}")

    def repl(match):
        return values[match.group(1)]

    return PLACE.sub(repl, text)


def placeholder_lines(text):
    """Secrets and passwords that were never replaced. Comments do not count."""
    found = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "CHANGE_ME" in line:
            found.append(stripped[:160])
    return found


def main(argv):
    if "--self-test" in argv:
        values = derive(load_config(HERE / "gs-config.yaml"))
        assert values["SEAT_PROBE_FAILURES"] == "450", values["SEAT_PROBE_FAILURES"]
        proxy = fill((HERE / "proxy.yaml").read_text(), values, HERE / "proxy.yaml")
        assert "hostNetwork:" not in proxy
        assert "hostPort:" not in proxy
        assert "k8s.v1.cni.cncf.io/networks: default/cs1-resident" in proxy
        assert "ovn.kubernetes.io/logical_switch: ovn-default" in proxy
        assert "cs1-resident.default.ovn.kubernetes.io/logical_switch: cs1-resident" in proxy
        seat = fill((HERE / "seat-direct.yaml").read_text(), values, HERE / "seat-direct.yaml")
        assert "ovn.kubernetes.io/logical_switch: ovn-default" in seat
        assert "cs1-resident" not in seat
        sample = (HERE / "orchestrator.yaml").read_text()
        assert placeholder_lines(sample), "sample manifest has no CHANGE_ME secrets"
        assert not placeholder_lines("# CHANGE_ME in a comment\nkey: value\n")
        print("render self-test ok")
        return 0
    values = derive(load_config(HERE / "gs-config.yaml"))
    names = ["gs-config.yaml", "orchestrator.yaml", "proxy.yaml"]
    if "--time-slicing" in argv:
        names.append("time-slicing.yaml")
    if "--seat" in argv:
        names.append("seat-direct.yaml")
    parts = []
    for name in names:
        path = HERE / name
        parts.append(fill(path.read_text(), values, path).strip())
    rendered = "\n---\n".join(parts) + "\n"
    if "--allow-placeholders" not in argv:
        found = placeholder_lines(rendered)
        if found:
            preview = "\n".join(found[:8])
            raise SystemExit(
                "refusing to render: replace CHANGE_ME secrets and Selkies passwords "
                "before apply. /admin and the cookie key would otherwise ship as the "
                "sample values.\n"
                + preview
                + "\nInspect only with: python3 deploy/render.py --allow-placeholders"
            )
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
