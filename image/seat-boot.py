#!/usr/bin/env python3
"""Apply gs-config to a seat's Sunshine files on every boot.

The orchestrator copies the ConfigMap into the seat env. This rewrites the
port family in sunshine.conf (Sunshine only has `port`; the other listeners
are that base plus the offsets) and installs the shared proxy certificate
into sunshine_state.json so the seat is already paired with every proxy.
"""

import json
import os
import sys
import time
import uuid
from hashlib import sha256


def upsert_conf(text, updates):
    """Replace `key = value` lines in order. Append keys that were absent."""
    seen = set()
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        key = None
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
        if key in updates:
            if key in seen:
                continue
            out.append(f"{key} = {updates[key]}")
            seen.add(key)
        else:
            out.append(line)
    for key, value in updates.items():
        if key not in seen:
            out.append(f"{key} = {value}")
    body = "\n".join(out)
    if not body.endswith("\n"):
        body += "\n"
    return body


def normalize_pem(text):
    text = (text or "").strip()
    if "-----BEGIN" not in text:
        raise ValueError("not a certificate")
    return text + "\n"


def same_pem(left, right):
    return "".join((left or "").split()) == "".join((right or "").split())


def cert_uuid(pem):
    digest = sha256(pem.encode()).hexdigest()[:32]
    return f"{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def install_proxy_cert(data, cert_pem, name):
    """Put the proxy cert in root.named_devices. One entry for `name`.

    Other paired clients are left alone. A previous proxy cert with the same
    name is replaced, so a regenerated proxy cert does not pile up.
    """
    if not isinstance(data, dict):
        data = {}
    root = data.get("root")
    if not isinstance(root, dict):
        root = {}
    devices = root.get("named_devices")
    if not isinstance(devices, list):
        devices = []
    pem = normalize_pem(cert_pem)
    kept = []
    found = False
    for device in devices:
        if not isinstance(device, dict):
            continue
        if device.get("name") == name or same_pem(device.get("cert"), pem):
            if found:
                continue
            device = dict(device)
            device["name"] = name
            device["cert"] = pem
            device["uuid"] = device.get("uuid") or cert_uuid(pem)
            device["enabled"] = True
            found = True
        kept.append(device)
    if not found:
        kept.append({"name": name, "cert": pem, "uuid": cert_uuid(pem), "enabled": True})
    root["named_devices"] = kept
    if not root.get("uniqueid"):
        root["uniqueid"] = uuid.uuid4().hex
    data["root"] = root
    return data


def managed_from_env(env):
    base_s = (env.get("SUNSHINE_BASE_PORT") or "").strip()
    if not base_s.isdigit():
        raise SystemExit("bad SUNSHINE_BASE_PORT")
    base = int(base_s)
    updates = {"port": str(base)}
    bind = (env.get("SUNSHINE_BIND") or "").strip()
    if bind and bind not in ("0.0.0.0", "::"):
        updates["bind_address"] = bind
    updates["address_family"] = (env.get("SUNSHINE_ADDRESS_FAMILY") or "ipv4").strip() or "ipv4"
    updates["origin_web_ui_allowed"] = (env.get("SUNSHINE_ORIGIN_WEB_UI") or "lan").strip() or "lan"
    updates["file_state"] = (env.get("SUNSHINE_STATE_FILE") or "sunshine_state.json").strip()
    for value in updates.values():
        if any(c in value for c in "\n\r\t#;|&$`<>'\"\\"):
            raise SystemExit("unsafe sunshine config value")
    _check_family(env, base)
    return updates


def _check_family(env, base):
    checks = (
        ("SUNSHINE_HTTPS_PORT", "SUNSHINE_HTTPS_OFFSET", -5),
        ("SUNSHINE_WEB_PORT", "SUNSHINE_WEB_OFFSET", 1),
        ("SUNSHINE_RTSP_PORT", "SUNSHINE_RTSP_OFFSET", 21),
    )
    for port_name, off_name, default_off in checks:
        raw = (env.get(port_name) or "").strip()
        if not raw:
            continue
        off = int((env.get(off_name) or str(default_off)).strip())
        if int(raw) != base + off:
            raise SystemExit(f"{port_name} {raw} != {base} + {off_name} ({off})")
    raw_ports = (env.get("SUNSHINE_UDP_PORTS") or "").strip()
    raw_offs = (env.get("SUNSHINE_UDP_OFFSETS") or "").strip()
    if raw_ports and raw_offs:
        offs = [int(part) for part in raw_offs.split(",") if part.strip()]
        ports = [int(part) for part in raw_ports.split(",") if part.strip()]
        expect = [base + off for off in offs]
        if ports != expect:
            raise SystemExit(f"SUNSHINE_UDP_PORTS {ports} != {expect}")


def read_cert(path):
    try:
        text = open(path).read()
    except OSError:
        return ""
    if "BEGIN CERTIFICATE" not in text:
        return ""
    return text


def wait_cert(path, seconds):
    deadline = time.time() + max(0, seconds)
    while True:
        text = read_cert(path)
        if text:
            return text
        if time.time() >= deadline:
            return ""
        time.sleep(0.2)


def write_state(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def load_state(path):
    if not os.path.isfile(path):
        return {}
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read {path}: {exc}")
    if not isinstance(data, dict):
        raise SystemExit(f"{path} is not a JSON object")
    return data


def apply_boot(conf_path, state_path, env):
    updates = managed_from_env(env)
    state_abs = os.path.abspath(state_path)
    if any(c in state_abs for c in "\n\r\t#;|&$`<>'\"\\"):
        raise SystemExit("unsafe sunshine state path")
    # Sunshine resolves a relative file_state under its appdata dir, which is
    # not the process cwd. Pin the file this boot just wrote.
    updates["file_state"] = state_abs
    previous = ""
    if os.path.isfile(conf_path):
        previous = open(conf_path).read()
    os.makedirs(os.path.dirname(conf_path) or ".", exist_ok=True)
    with open(conf_path, "w") as fh:
        fh.write(upsert_conf(previous, updates))
    cert_path = (env.get("GS_PROXY_CERT") or "").strip()
    if not cert_path:
        return updates, False
    required = (env.get("GS_PROXY_CERT_REQUIRED") or "1").strip().lower() not in ("0", "false", "no")
    wait = float(env.get("GS_PROXY_CERT_WAIT") or "60")
    pem = wait_cert(cert_path, wait)
    if not pem:
        if required:
            raise SystemExit(f"proxy cert missing at {cert_path}")
        print(f"seat-boot: no proxy cert at {cert_path}; sunshine will not trust the proxy", flush=True)
        return updates, False
    name = (env.get("GS_PROXY_CLIENT_NAME") or "gs-proxy").strip()
    if not name or any(c in name for c in "\n\r\t/\\"):
        raise SystemExit("bad GS_PROXY_CLIENT_NAME")
    data = install_proxy_cert(load_state(state_path), pem, name)
    write_state(state_path, data)
    return updates, True


def self_test():
    text = upsert_conf("capture = wlr\nport = 1\nport = 2\nencoder = nvenc\n", {"port": "47989"})
    assert text.count("port =") == 1
    assert "port = 47989" in text
    assert "capture = wlr" in text
    again = upsert_conf(text, {"port": "48000", "address_family": "ipv4"})
    assert "port = 48000" in again
    assert "address_family = ipv4" in again
    data = install_proxy_cert(
        {"root": {"uniqueid": "keep", "named_devices": [
            {"name": "phone", "cert": "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n", "uuid": "p"},
            {"name": "gs-proxy", "cert": "-----BEGIN CERTIFICATE-----\nOLD\n-----END CERTIFICATE-----\n", "uuid": "old"},
        ]}},
        "-----BEGIN CERTIFICATE-----\nNEW\n-----END CERTIFICATE-----",
        "gs-proxy",
    )
    devices = data["root"]["named_devices"]
    assert data["root"]["uniqueid"] == "keep"
    assert [d["name"] for d in devices] == ["phone", "gs-proxy"]
    assert "NEW" in devices[1]["cert"]
    assert devices[1]["uuid"] == "old"
    assert devices[1]["enabled"] is True
    fresh = install_proxy_cert({}, "-----BEGIN CERTIFICATE-----\nNEW\n-----END CERTIFICATE-----", "gs-proxy")
    assert fresh["root"]["named_devices"][0]["uuid"]
    assert fresh["root"]["named_devices"][0]["enabled"] is True
    turned_off = install_proxy_cert(
        {"root": {"named_devices": [
            {"name": "gs-proxy", "cert": "-----BEGIN CERTIFICATE-----\nOLD\n-----END CERTIFICATE-----\n",
             "uuid": "old", "enabled": False},
        ]}},
        "-----BEGIN CERTIFICATE-----\nNEW\n-----END CERTIFICATE-----",
        "gs-proxy",
    )
    assert turned_off["root"]["named_devices"][0]["enabled"] is True
    assert "NEW" in turned_off["root"]["named_devices"][0]["cert"]
    import tempfile
    boot = tempfile.mkdtemp()
    conf = os.path.join(boot, "sunshine.conf")
    state = os.path.join(boot, "sunshine_state.json")
    open(conf, "w").write("capture = wlr\nport = 1\n")
    cert_file = os.path.join(boot, "proxy-client.crt")
    open(cert_file, "w").write("-----BEGIN CERTIFICATE-----\nBOOT\n-----END CERTIFICATE-----\n")
    updates, paired = apply_boot(conf, state, {
        "SUNSHINE_BASE_PORT": "47989",
        "GS_PROXY_CERT": cert_file,
        "GS_PROXY_CERT_REQUIRED": "1",
        "GS_PROXY_CERT_WAIT": "0",
        "GS_PROXY_CLIENT_NAME": "gs-proxy",
    })
    assert paired
    assert updates["file_state"] == os.path.abspath(state)
    written = open(conf).read()
    assert f"file_state = {os.path.abspath(state)}" in written
    assert "port = 47989" in written
    saved = json.load(open(state))
    assert saved["root"]["named_devices"][0]["enabled"] is True
    assert saved["root"]["uniqueid"]
    env = {
        "SUNSHINE_BASE_PORT": "48000",
        "SUNSHINE_HTTPS_OFFSET": "-5",
        "SUNSHINE_HTTPS_PORT": "47995",
        "SUNSHINE_WEB_OFFSET": "1",
        "SUNSHINE_WEB_PORT": "48001",
        "SUNSHINE_RTSP_OFFSET": "21",
        "SUNSHINE_RTSP_PORT": "48021",
        "SUNSHINE_UDP_OFFSETS": "9,10",
        "SUNSHINE_UDP_PORTS": "48009,48010",
        "SUNSHINE_ORIGIN_WEB_UI": "lan",
        "SUNSHINE_STATE_FILE": "sunshine_state.json",
    }
    updates = managed_from_env(env)
    assert updates["port"] == "48000"
    bad = dict(env)
    bad["SUNSHINE_HTTPS_PORT"] = "111"
    try:
        managed_from_env(bad)
        raise SystemExit("mismatched https port accepted")
    except SystemExit as exc:
        if "SUNSHINE_HTTPS_PORT" not in str(exc):
            raise
    print("seat-boot self-test ok")


def main(argv):
    if "--self-test" in argv:
        self_test()
        return 0
    conf = state = None
    args = argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--conf":
            conf = args[i + 1]
            i += 2
            continue
        if args[i] == "--state":
            state = args[i + 1]
            i += 2
            continue
        raise SystemExit(f"unknown arg {args[i]}")
    if not conf or not state:
        raise SystemExit("need --conf and --state")
    updates, paired = apply_boot(conf, state, os.environ)
    print(
        f"seat-boot: sunshine port {updates['port']}"
        f" selkies {os.environ.get('SELKIES_PORT', '')}"
        f" proxy-cert {'installed' if paired else 'skipped'}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
