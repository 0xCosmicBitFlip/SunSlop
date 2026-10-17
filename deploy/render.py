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
    if "NAMESPACE" not in data or "PERSIST_SSD_ROOT" not in data or "PERSIST_HDD_ROOT" not in data:
        raise SystemExit(f"{path}: missing NAMESPACE, PERSIST_HDD_ROOT, or PERSIST_SSD_ROOT")
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


def csv_rows(orch_text):
    """games and disk columns. Both are required."""
    rows = {}
    in_csv = False
    for line in orch_text.splitlines():
        if not in_csv:
            if line.strip() == "users.csv: |":
                in_csv = True
            continue
        if line and not line.startswith(" "):
            break
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        parts = [part.strip() for part in raw.split(",")]
        if not parts[0] or parts[0].startswith("$"):
            continue
        if len(parts) != 5:
            raise SystemExit(f"users.csv {parts[0]}: want username,password,base_port,games,disk")
        games, disk = parts[3].lower(), parts[4].lower()
        if games not in ("common", "unique") or disk not in ("hdd", "ssd"):
            raise SystemExit(f"users.csv {parts[0]}: games is common or unique, disk is hdd or ssd")
        rows[parts[0]] = {"games": games, "disk": disk}
    return rows


def games_blocks(mode, host, ssd_host, mount, ssd_mount):
    """YAML pieces for seat-direct. unique omits both mounts."""
    if mode != "common":
        return {"GAMES_ENV": "", "GAMES_MOUNTS": "", "GAMES_VOLUMES": ""}
    if not host or not ssd_host:
        raise SystemExit("a common login needs GAMES_HOST and GAMESSD_HOST")
    env = (
        "        - name: GS_GAMES\n"
        f"          value: {mount}\n"
        "        - name: GS_GAMESSD\n"
        f"          value: {ssd_mount}\n"
    )
    mounts = (
        "        - name: games\n"
        f"          mountPath: {mount}\n"
        "        - name: gamessd\n"
        f"          mountPath: {ssd_mount}\n"
    )
    volumes = (
        "    - name: games\n"
        "      hostPath:\n"
        f"        path: {host}\n"
        "        type: DirectoryOrCreate\n"
        "    - name: gamessd\n"
        "      hostPath:\n"
        f"        path: {ssd_host}\n"
        "        type: DirectoryOrCreate\n"
    )
    return {"GAMES_ENV": env, "GAMES_MOUNTS": mounts, "GAMES_VOLUMES": volumes}


def apply_games(values, orch_text):
    rows = csv_rows(orch_text)
    if any(row["games"] == "common" for row in rows.values()):
        if not values.get("GAMES_HOST") or not values.get("GAMESSD_HOST"):
            raise SystemExit("a user is common but GAMES_HOST or GAMESSD_HOST is empty")
    user = values.get("SEAT_DIRECT_USER", "")
    row = rows.get(user) if user else None
    if user and row is None:
        raise SystemExit(f"{user} is not in users.csv")
    mode = row["games"] if row else "unique"
    disk = row["disk"] if row else "ssd"
    root = values["PERSIST_HDD_ROOT"] if disk == "hdd" else values["PERSIST_SSD_ROOT"]
    values["SEAT_HOME_HOST"] = f"{root}/{user}" if user else ""
    values.update(games_blocks(
        mode,
        values.get("GAMES_HOST", ""),
        values.get("GAMESSD_HOST", ""),
        values.get("GAMES_MOUNT", "/games"),
        values.get("GAMESSD_MOUNT", "/gamessd"),
    ))
    mounts = []
    volumes = []
    for name, key, dest in (
        ("games", "GAMES_HOST", "/scan/games"),
        ("gamessd", "GAMESSD_HOST", "/scan/gamessd"),
    ):
        host = values.get(key, "")
        if not host:
            continue
        mounts.append(f"            - name: {name}\n              mountPath: {dest}\n")
        volumes.append(
            f"        - name: {name}\n"
            "          hostPath:\n"
            f"            path: {host}\n"
            "          type: DirectoryOrCreate\n"
        )
    values["CLAMAV_MOUNTS"] = "".join(mounts)
    values["CLAMAV_VOLUMES"] = "".join(volumes)
    return values


def fill(text, values, path):
    missing = sorted(set(PLACE.findall(text)) - set(values))
    if missing:
        raise SystemExit(f"{path}: no value for {', '.join(missing)}")

    def repl(match):
        return values[match.group(1)]

    return PLACE.sub(repl, text)


def render_text(path, values):
    raw = path.read_text()
    if path.name == "clamav.yaml":
        script = (HERE / "clamav-scan.sh").read_text().rstrip("\n")
        indented = "\n".join(("    " + line) if line else "" for line in script.split("\n"))
        if "##CLAMAV_SCRIPT##" not in raw:
            raise SystemExit("clamav.yaml is missing the script marker")
        raw = raw.replace("##CLAMAV_SCRIPT##", indented)
    return fill(raw, values, path)
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
        apply_games(values, (HERE / "orchestrator.yaml").read_text())
        assert values["SEAT_PROBE_FAILURES"] == "450", values["SEAT_PROBE_FAILURES"]
        assert values["GAMES_ENV"] == ""
        rows = csv_rows("  users.csv: |\n    alice,pw,1,common,hdd\n    bob,pw,2,unique,ssd\n")
        assert rows["alice"] == {"games": "common", "disk": "hdd"}
        assert rows["bob"]["disk"] == "ssd"
        try:
            csv_rows("  users.csv: |\n    alice,pw,1,common\n")
            raise SystemExit("short users.csv row accepted")
        except SystemExit as exc:
            if "games,disk" not in str(exc):
                raise
        blocks = games_blocks("common", "/mnt/library", "/mnt/fast", "/games", "/gamessd")
        assert "readOnly" not in blocks["GAMES_MOUNTS"]
        assert "path: /mnt/fast" in blocks["GAMES_VOLUMES"]
        assert games_blocks("unique", "", "", "/games", "/gamessd")["GAMES_MOUNTS"] == ""
        try:
            games_blocks("common", "", "/mnt/fast", "/games", "/gamessd")
            raise SystemExit("common without GAMES_HOST accepted")
        except SystemExit as exc:
            if "GAMES_HOST" not in str(exc):
                raise
        proxy = render_text(HERE / "proxy.yaml", values)
        assert "hostNetwork:" not in proxy
        assert "hostPort:" not in proxy
        assert "k8s.v1.cni.cncf.io/networks: default/cs1-resident" in proxy
        assert "ovn.kubernetes.io/logical_switch: ovn-default" in proxy
        assert "cs1-resident.default.ovn.kubernetes.io/logical_switch: cs1-resident" in proxy
        orch = render_text(HERE / "orchestrator.yaml", values)
        assert "kind: StatefulSet" in orch
        assert "clusterIP: None" in orch
        cache = render_text(HERE / "cache.yaml", values)
        assert "clusterIP: None" in cache
        assert "redis:7.4-alpine" in cache
        assert "redis-sentinel" in cache
        seat = render_text(HERE / "seat-direct.yaml", values)
        assert "ovn.kubernetes.io/logical_switch: ovn-default" in seat
        assert "cs1-resident" not in seat
        assert "name: games" not in seat
        assert "name: gamessd" not in seat
        assert values["SEAT_HOME_HOST"].endswith("/gsuser0")
        clam = render_text(HERE / "clamav.yaml", values)
        assert "runtimeClassName: kata" in orch
        assert "runtimeClassName: kata" in proxy
        assert "runtimeClassName: kata" in cache
        assert "runtimeClassName: kata" in clam
        assert "clamscan" in clam
        assert "/scan/hdd" in clam
        assert "gs-layer" not in clam.split("scan.sh:", 1)[-1].split("---", 1)[0] or "CLAMAV_SKIP" in clam
        assert "##CLAMAV_SCRIPT##" not in clam
        sample = (HERE / "orchestrator.yaml").read_text()
        assert placeholder_lines(sample), "sample manifest has no CHANGE_ME secrets"
        assert not placeholder_lines("# CHANGE_ME in a comment\nkey: value\n")
        print("render self-test ok")
        return 0
    values = derive(load_config(HERE / "gs-config.yaml"))
    apply_games(values, (HERE / "orchestrator.yaml").read_text())
    names = ["gs-config.yaml", "orchestrator.yaml", "cache.yaml", "proxy.yaml", "clamav.yaml"]
    if "--time-slicing" in argv:
        names.append("time-slicing.yaml")
    if "--seat" in argv:
        names.append("seat-direct.yaml")
    parts = []
    for name in names:
        path = HERE / name
        parts.append(render_text(path, values).strip())
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
