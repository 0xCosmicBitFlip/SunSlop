"""Shared proxy certificate and whether a seat has installed it."""
import json
import os
import threading
import time
import uuid

try:
    import fcntl
except ImportError:
    fcntl = None

from gs.protocol import canonical_pem, fingerprint, log, make_cert

class Store:
    """Shared by every proxy. The file lives on the persist volume.

    server_cert is generated on first start and then left alone. Every proxy
    presents it to Moonlight and to Sunshine. The public half is also written
    beside the store so a seat can install it at boot.
    """

    def __init__(self, path, cert_path=None):
        self.path = path
        parent = os.path.dirname(os.path.abspath(path)) or "."
        self.cert_path = cert_path or os.path.join(parent, "proxy-client.crt")
        self._lock_path = path + ".lock"
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        os.makedirs(os.path.dirname(self.cert_path) or ".", exist_ok=True)
        self._lock = threading.Lock()
        with self._lock:
            self._exclusive(self._ensure)

    def _empty(self):
        cert, key = make_cert("gs-proxy")
        return {
            "server_cert": cert,
            "server_key": key,
            "uniqueid": uuid.uuid4().hex,
            "clients": [],
            "pods": {},
            "pending": {},
        }

    def _exclusive(self, fn):
        with open(self._lock_path, "a+") as lock:
            if fcntl:
                fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                return fn()
            finally:
                if fcntl:
                    fcntl.flock(lock, fcntl.LOCK_UN)

    def _ensure(self):
        if not os.path.exists(self.path):
            self._write(self._empty())
            return
        self._publish((self._read() or {}).get("server_cert") or "")

    def _read(self):
        with open(self.path) as fh:
            return json.load(fh)

    def _write(self, data):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(data, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        self._publish(data.get("server_cert") or "")

    def _publish(self, cert):
        if not cert or not self.cert_path:
            return
        text = cert if str(cert).endswith("\n") else str(cert) + "\n"
        data = text.encode()
        try:
            with open(self.cert_path, "rb") as fh:
                current = fh.read()
        except OSError:
            current = b""
        if current == data:
            return
        # The seat mounts this path as a hostPath file. That mount is the
        # inode. os.replace would leave the seat reading the old empty file.
        fd = os.open(self.cert_path, os.O_WRONLY | os.O_CREAT, 0o644)
        try:
            os.ftruncate(fd, 0)
            view = data
            while view:
                wrote = os.write(fd, view)
                if wrote <= 0:
                    raise OSError("short write publishing the proxy certificate")
                view = view[wrote:]
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.chmod(self.cert_path, 0o644)
        except OSError:
            pass

    def update(self, fn):
        with self._lock:
            def run():
                data = self._read()
                result = fn(data)
                self._write(data)
                return result
            return self._exclusive(run)

    def snapshot(self):
        with self._lock:
            return self._exclusive(self._read)

    def server_material(self):
        data = self.snapshot()
        return data["server_cert"], data["server_key"], data["uniqueid"]

    def client_for_der(self, der):
        if not der:
            return None
        pem = canonical_pem(der)
        fp = fingerprint(pem)
        for client in self.snapshot()["clients"]:
            if client.get("fingerprint") == fp and client.get("gsuser"):
                return client
        return None

    def user_names(self):
        return sorted({c["gsuser"] for c in self.snapshot()["clients"] if c.get("gsuser")})


def sunshine_state_path(root, gsuser, config_rel=".config/sunshine", state_name="sunshine_state.json"):
    rel = (config_rel or ".config/sunshine").strip("/")
    name = state_name or "sunshine_state.json"
    return os.path.join(root, gsuser, rel, name)


def _iter_state_certs(data):
    root = data.get("root", data) if isinstance(data, dict) else {}
    if not isinstance(root, dict):
        return
    for key in ("named_devices", "namedDevices"):
        for device in root.get(key) or []:
            if isinstance(device, dict) and device.get("cert"):
                yield device.get("cert")
    for device in root.get("devices") or []:
        if not isinstance(device, dict):
            continue
        if device.get("cert"):
            yield device.get("cert")
        for key in ("named_certs", "namedCerts", "certs"):
            for item in device.get(key) or []:
                if isinstance(item, dict) and item.get("cert"):
                    yield item.get("cert")
                elif isinstance(item, str):
                    yield item


def state_has_cert(root, gsuser, cert_pem, config_rel=".config/sunshine", state_name="sunshine_state.json"):
    path = sunshine_state_path(root, gsuser, config_rel, state_name)
    if not os.path.isfile(path):
        return None
    try:
        data = json.load(open(path))
    except (OSError, json.JSONDecodeError):
        return None
    want = fingerprint(cert_pem)
    for cert in _iter_state_certs(data):
        try:
            raw = cert.encode() if isinstance(cert, str) else cert
            if fingerprint(canonical_pem(raw)) == want:
                return True
        except Exception:
            continue
    return False

