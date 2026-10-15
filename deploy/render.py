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
    return values


def fill(text, values, path):
    missing = sorted(set(PLACE.findall(text)) - set(values))
    if missing:
        raise SystemExit(f"{path}: no value for {', '.join(missing)}")

    def repl(match):
        return values[match.group(1)]

    return PLACE.sub(repl, text)


def main(argv):
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
    sys.stdout.write("\n---\n".join(parts) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
