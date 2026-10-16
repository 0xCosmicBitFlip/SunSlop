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

CERT_PROXY (the default) is the public Sunshine listener. Moonlight dials
the configured Sunshine ports (SUNSHINE_BASE). TLS on the HTTPS port is
terminated, the client certificate selects the login, and a second TLS
session to the seat presents the shared proxy certificate. Every seat
listens on SUNSHINE_BASE.

CERT_PROXY=false is the older layout: each users.csv base owns an external
span, and that span is shifted onto the seat's default ports. A seat on
another node still resets the client.

Idle deletes the pod. Home, pairing, and the package layer stay on disk.
"""

import base64
import hmac
import hashlib
import json
import os
import selectors
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

PORT_LO = -5   # 47984 HTTPS when the external base is 47989
PORT_HI = 21   # 48010 RTSP / trailing UDP
SPAN = PORT_HI - PORT_LO + 1  # 27
SUNSHINE_BASE = 47989  # every seat listens here, whatever the client dialed
ACTIVITY = "gamestream.local/last-activity"
ADVERTISE = "gamestream.local/advertise"

HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}


def log(msg):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(f"{ts} {msg}", flush=True)


def port_span(base):
    return range(base + PORT_LO, base + PORT_HI + 1)


def pod_port(external, user_base, sunshine_base=SUNSHINE_BASE):
    """Map a client-facing port onto the seat's Sunshine span."""
    return sunshine_base + (external - user_base)


def still_active(local_idle, remote_idle, limit):
    """Keep the seat if this node or another node's proxy has been busy."""
    samples = [v for v in (local_idle, remote_idle) if v is not None]
    if not samples:
        return True
    return min(samples) < limit


class Place:
    """Where a seat ended up, relative to the proxy that asked."""

    __slots__ = ("kind", "info", "proxy_host", "node")

    def __init__(self, kind, info="", proxy_host="", node=""):
        self.kind = kind
        self.info = info or ""
        self.proxy_host = proxy_host or ""
        self.node = node or ""

    def __iter__(self):
        yield self.kind
        yield self.info


def pick_node(prefer, nodes, has_room):
    """nodes maps node name to the address clients should retry.
    Prefer `prefer` when it has room, otherwise the next name that does.
    """
    ordered = []
    if prefer and prefer in nodes:
        ordered.append(prefer)
    ordered.extend(node for node in sorted(nodes) if node not in ordered)
    for node in ordered:
        if has_room(node):
            return node, nodes[node]
    return None, ""


def advertise_host(pod):
    ann = ((pod.get("metadata") or {}).get("annotations") or {})
    stamped = (ann.get(ADVERTISE) or "").strip()
    if stamped:
        return stamped
    return ((pod.get("status") or {}).get("hostIP") or "").strip()


def api_token(secret):
    return hmac.new(secret, b"gs-orch-api-v1", hashlib.sha256).hexdigest()


def public_base(cfg, host):
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    tmpl = (getattr(cfg, "public_http_base", "") or "").strip()
    if tmpl:
        return tmpl.replace("{host}", host).rstrip("/")
    return f"http://{host}:{cfg.http_port}"


def place_dict(place):
    ready = place.kind in ("local", "remote")
    return {
        "kind": place.kind,
        "podIP": place.info if ready else "",
        "info": place.info,
        "proxyHost": place.proxy_host,
        "node": place.node,
        "detail": "" if ready else place.info,
    }


def place_from_api(data):
    kind = data.get("kind") or "error"
    if kind in ("local", "remote"):
        info = data.get("podIP") or data.get("info") or ""
    else:
        info = data.get("detail") or data.get("info") or ""
    return Place(kind, info, data.get("proxyHost") or "", data.get("node") or "")


@dataclass(frozen=True)
class User:
    name: str
    password: str
    base: int

    @property
    def pod_name(self):
        return "gs-" + self.name


DEFAULT_RESERVED = ("common", "layer", "proxy", "gs-layer")


def reserved_names(*extra):
    names = set(DEFAULT_RESERVED)
    for item in extra:
        if item:
            names.add(str(item).strip("/"))
    return names


def load_users(text, reserved=None):
    """username,password,sunshine_base_port. '#' comments. No commas in fields."""
    users = {}
    taken = []
    blocked = reserved_names() if reserved is None else set(reserved)
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) != 3:
            raise ValueError(f"{lineno}: want username,password,base_port")
        name, password, base_s = parts
        if not _ok_name(name, blocked):
            raise ValueError(f"{lineno}: bad username {name!r}")
        if not password or password.startswith("CHANGE_ME"):
            raise ValueError(f"{lineno}: password is empty or still the CHANGE_ME placeholder")
        base = int(base_s)
        if not 1029 <= base <= 65514:
            raise ValueError(f"{lineno}: base port {base} out of range")
        lo, hi = base + PORT_LO, base + PORT_HI
        if lo < 1 or hi > 65535:
            raise ValueError(f"{lineno}: span {lo}-{hi} does not fit")
        for olo, ohi, other in taken:
            if not (hi < olo or lo > ohi):
                raise ValueError(f"{lineno}: {name} {lo}-{hi} overlaps {other}")
        taken.append((lo, hi, name))
        users[name] = User(name, password, base)
    return users


def _ok_name(name, reserved=None):
    blocked = reserved_names() if reserved is None else reserved
    if name in blocked or len(name) > 40:
        return False
    if not name or not name[0].isalpha() or not name.islower():
        return False
    return all(c.islower() or c.isdigit() or c == "-" for c in name)


def pick_gpu(assigned, gpu_count, sessions_per_gpu):
    """Least-loaded index. Ties go to the lower index, which is also how the
    NVIDIA device plugin packs time-sliced replicas. None if every GPU is at cap."""
    counts = [0] * gpu_count
    for gpu in assigned:
        if isinstance(gpu, int) and 0 <= gpu < gpu_count:
            counts[gpu] += 1
    best = min(range(gpu_count), key=lambda i: (counts[i], i))
    if counts[best] >= sessions_per_gpu:
        return None
    return best


def issue_token(username, secret, ttl, now=None):
    exp = int((now if now is not None else time.time()) + ttl)
    payload = f"{username}|{exp}".encode()
    sig = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=") + "." + sig


def read_token(token, secret, now=None):
    if not token or "." not in token:
        return None
    body, sig = token.rsplit(".", 1)
    pad = "=" * (-len(body) % 4)
    try:
        payload = base64.urlsafe_b64decode(body + pad)
    except (ValueError, base64.binascii.Error):
        return None
    expect = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, sig):
        return None
    try:
        username, exp_s = payload.decode().split("|", 1)
        exp = int(exp_s)
    except (UnicodeError, ValueError):
        return None
    if exp < int(now if now is not None else time.time()):
        return None
    if not _ok_name(username):
        return None
    return username


class Directory:
    """Who may have a seat. Authentication is separate so SAML can replace the password."""

    def __init__(self, path, reserved=None):
        self.path = path
        self.reserved = reserved_names() if reserved is None else set(reserved)
        self._mtime = None
        self.users = {}
        self.by_port = {}
        self.reload(force=True)

    def reload(self, force=False):
        try:
            st = os.stat(self.path)
        except OSError as exc:
            log(f"users file: {exc}")
            return
        if not force and st.st_mtime == self._mtime:
            return
        try:
            users = load_users(open(self.path).read(), self.reserved)
        except (OSError, ValueError) as exc:
            log(f"users file rejected, keeping previous: {exc}")
            return
        by_port = {}
        for user in users.values():
            for port in port_span(user.base):
                by_port[port] = user
        self.users = users
        self.by_port = by_port
        self._mtime = st.st_mtime
        log(f"users: {', '.join(u.name + '@' + str(u.base) for u in users.values()) or '(none)'}")

    def authenticate(self, username, password):
        user = self.users.get(username)
        if user is None or not hmac.compare_digest(user.password, password):
            return None
        return user

    def get(self, username):
        return self.users.get(username)


class SamlAuthenticator:
    """Keycloak later. Directory stays the authorization list.

    A future implementation verifies the SAMLResponse posted to /saml/acs,
    reads the NameID (or a configured attribute), and returns that string.
    It must already be a username in users.csv. The password column is then
    ignored. Session cookies are still issued by issue_token(); nothing in
    the proxy or the seat pod changes.
    """

    def consume(self, payload):
        raise NotImplementedError("SAML is not wired; /saml/acs returns 501")


class Kube:
    def __init__(self, namespace, seat_label="gamestream"):
        host = os.environ["KUBERNETES_SERVICE_HOST"]
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        self.base = f"https://{host}:{port}"
        self.ns = namespace or open("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read().strip()
        self.token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        self.ca = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        self.seat_label = seat_label
        self._cache = []
        self._cached = 0.0

    def _token(self):
        return open(self.token_path).read().strip()

    def request(self, method, path, body=None, content_type="application/json"):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Authorization", "Bearer " + self._token())
        if data is not None:
            req.add_header("Content-Type", content_type)
        ctx = ssl.create_default_context(cafile=self.ca)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                raw = resp.read()
                return resp.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                parsed = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                parsed = {"message": raw.decode("utf-8", "replace")[:400]}
            return exc.code, parsed

    def invalidate(self):
        self._cached = 0.0

    def list_seats(self):
        now = time.monotonic()
        if self._cache and now - self._cached < 1.0:
            return self._cache
        code, data = self.request(
            "GET",
            f"/api/v1/namespaces/{self.ns}/pods?labelSelector={urllib.parse.quote('app=' + self.seat_label, safe='')}",
        )
        if code != 200:
            log(f"list pods: {code} {data}")
            return self._cache
        self._cache = data.get("items", [])
        self._cached = now
        return self._cache

    def get_pod(self, name):
        code, data = self.request("GET", f"/api/v1/namespaces/{self.ns}/pods/{name}")
        if code == 404:
            return None
        if code != 200:
            log(f"get {name}: {code} {data}")
            return None
        return data

    def create_pod(self, pod):
        self.invalidate()
        return self.request("POST", f"/api/v1/namespaces/{self.ns}/pods", pod)

    def delete_pod(self, name):
        self.invalidate()
        return self.request(
            "DELETE",
            f"/api/v1/namespaces/{self.ns}/pods/{name}?gracePeriodSeconds=15",
        )

    def patch_pod(self, name, body):
        self.invalidate()
        return self.request(
            "PATCH",
            f"/api/v1/namespaces/{self.ns}/pods/{name}",
            body,
            "application/merge-patch+json",
        )

    def list_apps(self, names):
        found = []
        seen = set()
        for name in names:
            code, data = self.request(
                "GET",
                f"/api/v1/namespaces/{self.ns}/pods?labelSelector={urllib.parse.quote('app=' + name, safe='')}",
            )
            if code != 200:
                continue
            for pod in data.get("items", []):
                uid = ((pod.get("metadata") or {}).get("uid")
                       or (pod.get("metadata") or {}).get("name"))
                if uid in seen:
                    continue
                seen.add(uid)
                found.append(pod)
        return found


def pod_gpu(pod):
    raw = (pod.get("metadata", {}).get("labels") or {}).get("gamestream.local/gpu")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def pod_phase(pod):
    return (pod.get("status") or {}).get("phase") or ""


def pod_ip(pod):
    return (pod.get("status") or {}).get("podIP")


def activity_unix(pod):
    raw = ((pod.get("metadata") or {}).get("annotations") or {}).get(ACTIVITY)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def pod_node(pod):
    return (pod.get("spec") or {}).get("nodeName")


def pod_ready(pod):
    for cond in (pod.get("status") or {}).get("conditions") or []:
        if cond.get("type") == "Ready" and cond.get("status") == "True":
            return True
    return False


class Seats:
    def __init__(self, cfg, directory, kube):
        self.cfg = cfg
        self.directory = directory
        self.kube = kube
        self._locks = {}
        self._guard = threading.Lock()
        self.activity = {}
        self._patched = {}
        self.starting = set()

    def _lock(self, name):
        with self._guard:
            lock = self._locks.get(name)
            if lock is None:
                lock = threading.Lock()
                self._locks[name] = lock
            return lock

    def touch(self, name):
        now = time.monotonic()
        self.activity[name] = now
        if now - self._patched.get(name, 0) < 30:
            return
        self._patched[name] = now
        threading.Thread(target=self._announce, args=(name,), daemon=True).start()

    def _announce(self, name):
        user = self.directory.get(name)
        if user is None:
            return
        try:
            code, data = self.kube.patch_pod(
                user.pod_name,
                {"metadata": {"annotations": {ACTIVITY: str(int(time.time()))}}},
            )
        except Exception as exc:
            log(f"{name}: activity patch {exc}")
            return
        if code == 404:
            return
        if code not in (200, 201):
            msg = data.get("message", data) if isinstance(data, dict) else data
            log(f"{name}: activity patch {code} {msg}")

    def lookup(self, user, prefer_node=None):
        """Ready seat, or None. Does not create it. kind is local to prefer_node."""
        if user is None:
            return None
        prefer = prefer_node or self.cfg.node
        pod = self.kube.get_pod(user.pod_name)
        if not pod or pod_phase(pod) != "Running" or not pod_ready(pod):
            return None
        ip = pod_ip(pod) or ""
        if not ip:
            return None
        node = pod_node(pod) or ""
        host = self._host_for(node)
        kind = "local" if node == prefer else "remote"
        return Place(kind, ip, host, node)

    def ensure(self, user, prefer_node=None):
        """Place is local only when the seat is on prefer_node (this proxy)."""
        self.touch(user.name)
        prefer = prefer_node or self.cfg.node
        with self._lock(user.name):
            self.starting.add(user.name)
            try:
                return self._ensure(user, prefer)
            finally:
                self.starting.discard(user.name)

    def _from_pod(self, user, pod, prefer):
        node = pod_node(pod) or ""
        host = self._host_for(node)
        if node and node != prefer:
            ip = pod_ip(pod) if pod_ready(pod) and pod_phase(pod) == "Running" else ""
            return Place("remote", ip or "", host, node)
        ip = self._wait_ready(user, pod)
        if ip:
            return Place("local", ip, host or self._host_for(prefer), node or prefer)
        return Place("error", "existing pod did not become ready", host, node)

    def _ensure(self, user, prefer):
        pod = self.kube.get_pod(user.pod_name)
        if pod and pod_phase(pod) in ("Failed", "Succeeded"):
            log(f"{user.name}: clearing {pod_phase(pod)} pod")
            self.kube.delete_pod(user.pod_name)
            pod = None
            for _ in range(20):
                if self.kube.get_pod(user.pod_name) is None:
                    break
                time.sleep(0.5)
        if pod:
            return self._from_pod(user, pod, prefer)
        node, host = self._choose(prefer)
        if not node:
            if self.cfg.role == "orchestrator" and not self._frontend_nodes():
                return Place("error", "no proxy is ready")
            return Place("full", "")
        gpu = self._pick(node)
        if gpu is None:
            return Place("full", "")
        body = seat_pod(self.cfg, user, gpu, node)
        code, data = self.kube.create_pod(body)
        if code == 409:
            pod = self.kube.get_pod(user.pod_name)
            if pod:
                return self._from_pod(user, pod, prefer)
            return Place("error", "create conflict but pod is gone")
        if code not in (200, 201):
            msg = (data or {}).get("message", data)
            log(f"{user.name}: create {code} {msg}")
            return Place("error", str(msg)[:300])
        log(f"{user.name}: creating on {node} gpu {gpu} "
            f"sunshine {self.cfg.sunshine_base + PORT_LO}-{self.cfg.sunshine_base + PORT_HI}")
        if node != prefer:
            return Place("remote", "", host, node)
        ip = self._wait_ready(user, data)
        if not ip:
            return Place("error", "pod never became ready", host, node)
        return Place("local", ip, host, node)

    def _frontend_nodes(self):
        labels = {self.cfg.proxy_label}
        if self.cfg.role != "orchestrator":
            labels.add(self.cfg.orch_label)
        out = {}
        for pod in self.kube.list_apps(labels):
            if pod_phase(pod) not in ("Pending", "Running"):
                continue
            node = pod_node(pod)
            if not node:
                continue
            app = ((pod.get("metadata") or {}).get("labels") or {}).get("app")
            host = advertise_host(pod)
            if node not in out or app == self.cfg.proxy_label:
                out[node] = host or out.get(node, "")
        return out

    def _host_for(self, node):
        if not node:
            return ""
        nodes = self._frontend_nodes()
        if nodes.get(node):
            return nodes[node]
        if node == self.cfg.node and self.cfg.advertise:
            return self.cfg.advertise
        return ""

    def _choose(self, prefer):
        nodes = self._frontend_nodes()
        if not nodes:
            if self.cfg.role == "orchestrator":
                return None, ""
            return prefer, self.cfg.advertise or ""
        return pick_node(prefer, nodes, lambda node: self._pick(node) is not None)

    def _pick(self, node=None):
        node = node or self.cfg.node
        assigned = []
        for pod in self.kube.list_seats():
            if pod_node(pod) != node:
                continue
            if pod_phase(pod) not in ("Pending", "Running"):
                continue
            gpu = pod_gpu(pod)
            if gpu is not None:
                assigned.append(gpu)
        return pick_gpu(assigned, self.cfg.gpu_count, self.cfg.sessions_per_gpu)

    def _wait_ready(self, user, pod):
        deadline = time.monotonic() + self.cfg.ready_timeout
        name = user.pod_name
        while time.monotonic() < deadline:
            self.touch(user.name)
            if pod and pod_ready(pod) and pod_ip(pod):
                return pod_ip(pod)
            time.sleep(1)
            pod = self.kube.get_pod(name)
            if pod is None:
                return None
            if pod_phase(pod) in ("Failed", "Succeeded"):
                log(f"{user.name}: pod {pod_phase(pod)} while waiting")
                return None
        log(f"{user.name}: not Ready after {self.cfg.ready_timeout}s")
        return None

    def reap(self):
        now = time.monotonic()
        now_w = time.time()
        for pod in self.kube.list_seats():
            if pod_phase(pod) not in ("Pending", "Running"):
                continue
            labels = pod.get("metadata", {}).get("labels") or {}
            name = labels.get("gamestream.local/user")
            if not name or name in self.starting:
                continue
            ann = activity_unix(pod)
            remote_idle = None if ann is None else now_w - ann
            last = self.activity.get(name)
            if last is None and remote_idle is None:
                self.activity[name] = now
                continue
            local_idle = None if last is None else now - last
            if still_active(local_idle, remote_idle, self.cfg.idle_seconds):
                continue
            log(f"{name}: idle, deleting pod")
            code, data = self.kube.delete_pod(pod["metadata"]["name"])
            if code not in (200, 202, 404):
                log(f"{name}: delete {code} {data}")
            self.activity.pop(name, None)

    def owner_url(self, node):
        host = self._host_for(node)
        if not host:
            return None
        return public_base(self.cfg, host)


@dataclass
class Config:
    node: str
    namespace: str
    users_file: str
    secret: bytes
    cookie_ttl: int
    idle_seconds: int
    persist_root: str
    common_host: str
    common_mount: str
    image: str
    runtime: str
    gpu_count: int
    sessions_per_gpu: int
    http_port: int
    selkies_port: int
    ready_timeout: int
    device_plugin: bool
    http_foreign: str
    memory_limit: str
    cpu_limit: str
    cert_proxy: bool = True
    proxy_store: str = "/var/lib/gs-proxy/store.json"
    admin_password: str = ""
    sunshine_web_user: str = ""
    sunshine_web_password: str = ""
    common_dir: str = "common"
    layer_dir: str = "gs-layer"
    proxy_dir: str = "proxy"
    layer_host: str = ""
    layer_mount: str = "/gs-layer"
    seat_user: str = "gsuser"
    seat_uid: int = 1000
    seat_gid: int = 1000
    seat_home: str = "/home/gsuser"
    xdg_runtime: str = "/run/user/1000"
    wayland_display: str = "wayland-0"
    sunshine_base: int = SUNSHINE_BASE
    memory_request: str = "8Gi"
    cpu_request: str = "2"
    kata_memory: str = "16384"
    nvidia_caps: str = "compute,utility,graphics,display,video"
    selkies_encoder: str = "nvh264enc"
    persist_mount: str = "/var/lib/gs-persist"
    role: str = "all"
    orch_url: str = ""
    https_offset: int = -5
    web_offset: int = 1
    rtsp_offset: int = 21
    udp_offsets: tuple = (9, 10, 11, 13, 21)
    proxy_label: str = "gs-proxy"
    orch_label: str = "gs-orchestrator"
    seat_label: str = "gamestream"
    advertise: str = ""
    proxy_cert_publish: str = ""
    proxy_cert_host: str = ""
    proxy_cert_mount: str = "/etc/gamestream/proxy-client.crt"
    proxy_client_name: str = "gs-proxy"
    proxy_cert_required: bool = True
    sunshine_bind: str = "0.0.0.0"
    sunshine_address_family: str = "ipv4"
    sunshine_origin: str = "lan"
    sunshine_state_file: str = "sunshine_state.json"
    sunshine_config_rel: str = ".config/sunshine"
    selkies_addr: str = "0.0.0.0"
    public_http_base: str = ""
    kata_firmware: str = "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd"
    kata_firmware_vars: str = "/usr/share/edk2/ovmf/OVMF_VARS.fd"
    kata_secure_boot: bool = True
    tpu_emulation: bool = True
    tpu_state_dir: str = "tpu"


def env_get(name, default):
    val = os.environ.get(name)
    if val is None or val == "":
        return default
    return val


def env_int(name, default):
    return int(env_get(name, str(default)))


def env_csv_ints(name, default):
    raw = env_get(name, default)
    out = []
    for part in str(raw).split(","):
        part = part.strip()
        if part:
            out.append(int(part))
    return tuple(out)


def env_bool(name, default):
    return env_get(name, "true" if default else "false").lower() not in ("0", "false", "no")


def _safe(value, label):
    if not value or any(c in value for c in "\n\r\t;|&$`<>'\"\\"):
        raise SystemExit(f"bad {label}")
    return value


def _dir_name(value, label):
    name = value.strip("/")
    if not name or name in (".", "..") or "/" in name:
        raise SystemExit(f"bad {label}")
    return name


def derive_storage(persist_root, common_dir, layer_dir, proxy_dir, persist_mount,
                   common_host="", layer_host="", proxy_store="", cert_file="proxy-client.crt"):
    """Host homes are <root>/<login>. The three shared dirs sit beside them.
    The proxy file is <persist_mount>/<proxy_dir>/store.json inside the proxy.
    The public cert is the sibling file seats mount read-only.
    """
    root = persist_root.rstrip("/")
    mount = persist_mount.rstrip("/")
    common = common_host or f"{root}/{common_dir}"
    layer = layer_host or f"{root}/{layer_dir}"
    store = proxy_store or f"{mount}/{proxy_dir}/store.json"
    name = (cert_file or "proxy-client.crt").strip("/")
    cert_publish = f"{mount}/{proxy_dir}/{name}"
    cert_host = f"{root}/{proxy_dir}/{name}"
    return common, layer, store, cert_publish, cert_host


def load_config():
    secret_path = env_get("COOKIE_SECRET_FILE", "/etc/gamestream/cookie.secret")
    secret = open(secret_path, "rb").read().strip()
    if len(secret) < 16 or b"CHANGE_ME" in secret:
        raise SystemExit("cookie secret must be at least 16 bytes and must not be the CHANGE_ME placeholder")
    admin_password = os.environ.get("ADMIN_PASSWORD", "")
    if not admin_password.strip() or "CHANGE_ME" in admin_password:
        raise SystemExit(
            "ADMIN_PASSWORD is empty or still the CHANGE_ME placeholder. "
            "An empty password would leave /admin open on the proxy."
        )
    flag = env_get("CERT_PROXY", "true").lower()
    persist_root = env_get("PERSIST_ROOT", "/var/lib/gamestream/persistent")
    common_dir = _dir_name(env_get("COMMON_DIR", "common"), "COMMON_DIR")
    layer_dir = _dir_name(env_get("LAYER_DIR", "gs-layer"), "LAYER_DIR")
    proxy_dir = _dir_name(env_get("PROXY_DIR", "proxy"), "PROXY_DIR")
    persist_mount = _safe(env_get("PERSIST_MOUNT", "/var/lib/gs-persist"), "PERSIST_MOUNT")
    role = env_get("GS_ROLE", "all").strip().lower()
    if role not in ("all", "proxy", "orchestrator"):
        raise SystemExit(f"bad GS_ROLE {role}")
    cert_file = _safe(env_get("PROXY_CLIENT_CERT", "proxy-client.crt"), "PROXY_CLIENT_CERT")
    common_host, layer_host, proxy_store, cert_publish, cert_host = derive_storage(
        persist_root, common_dir, layer_dir, proxy_dir, persist_mount,
        common_host=os.environ.get("COMMON_HOST_PATH", ""),
        layer_host=os.environ.get("LAYER_HOST_PATH", ""),
        proxy_store=os.environ.get("PROXY_STORE", ""),
        cert_file=cert_file,
    )
    seat_user = _safe(env_get("SEAT_USER", "gsuser"), "SEAT_USER")
    seat_uid = env_int("SEAT_UID", 1000)
    seat_gid = env_int("SEAT_GID", 1000)
    seat_home = _safe(env_get("SEAT_HOME", "/home/" + seat_user), "SEAT_HOME")
    kata_secure_boot = env_bool("KATA_SECURE_BOOT", True)
    kata_firmware = ""
    kata_firmware_vars = ""
    if kata_secure_boot:
        kata_firmware = _safe(
            env_get("KATA_FIRMWARE", "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd"),
            "KATA_FIRMWARE",
        )
        kata_firmware_vars = _safe(
            env_get("KATA_FIRMWARE_VARS", "/usr/share/edk2/ovmf/OVMF_VARS.fd"),
            "KATA_FIRMWARE_VARS",
        )
    tpu_emulation = env_bool("TPU_EMULATION", True)
    tpu_state_dir = "tpu"
    if tpu_emulation:
        tpu_state_dir = _dir_name(env_get("TPU_STATE_DIR", "tpu"), "TPU_STATE_DIR")
        if tpu_state_dir == "uefi":
            raise SystemExit("bad TPU_STATE_DIR")
    xdg_runtime = _safe(env_get("XDG_RUNTIME_DIR", f"/run/user/{seat_uid}"), "XDG_RUNTIME_DIR")
    wayland_display = _safe(env_get("WAYLAND_DISPLAY", "wayland-0"), "WAYLAND_DISPLAY")
    common_mount = _safe(
        env_get("COMMON_MOUNT", env_get("COMMON_MOUNT_PATH", "/games")), "COMMON_MOUNT"
    )
    layer_mount = _safe(env_get("LAYER_MOUNT", "/gs-layer"), "LAYER_MOUNT")
    http_port = env_int("HTTP_PORT", 8080)
    orch_url = env_get("ORCH_URL", "")
    if role == "proxy" and not orch_url:
        orch_url = f"http://{env_get('ORCH_NAME', 'gs-orchestrator')}:{http_port}"
    return Config(
        node=os.environ["NODE_NAME"],
        namespace=os.environ.get("POD_NAMESPACE", ""),
        users_file=env_get("USERS_FILE", "/etc/gamestream/users.csv"),
        secret=secret,
        cookie_ttl=env_int("COOKIE_TTL", 30 * 24 * 3600),
        idle_seconds=env_int("IDLE_SECONDS", 600),
        persist_root=persist_root.rstrip("/"),
        common_host=common_host,
        common_mount=common_mount,
        image=env_get("SEAT_IMAGE", "gamestream:local"),
        runtime=env_get("RUNTIME_CLASS", "nvkvm-kata"),
        gpu_count=env_int("GPU_COUNT", 2),
        sessions_per_gpu=env_int("SESSIONS_PER_GPU", 8),
        http_port=http_port,
        selkies_port=env_int("SELKIES_PORT", 8082),
        ready_timeout=env_int("READY_TIMEOUT", 900),
        device_plugin=env_get("DEVICE_PLUGIN", "true").lower() not in ("0", "false", "no"),
        http_foreign=env_get("HTTP_FOREIGN", "redirect"),
        memory_limit=env_get("SEAT_MEMORY_LIMIT", "16Gi"),
        cpu_limit=env_get("SEAT_CPU_LIMIT", "8"),
        cert_proxy=flag not in ("0", "false", "no"),
        proxy_store=proxy_store,
        admin_password=admin_password,
        sunshine_web_user=os.environ.get("SUNSHINE_WEB_USER", ""),
        sunshine_web_password=os.environ.get("SUNSHINE_WEB_PASSWORD", ""),
        common_dir=common_dir,
        layer_dir=layer_dir,
        proxy_dir=proxy_dir,
        layer_host=layer_host,
        layer_mount=layer_mount,
        seat_user=seat_user,
        seat_uid=seat_uid,
        seat_gid=seat_gid,
        seat_home=seat_home,
        xdg_runtime=xdg_runtime,
        wayland_display=wayland_display,
        sunshine_base=env_int("SUNSHINE_BASE", SUNSHINE_BASE),
        memory_request=env_get("SEAT_MEMORY_REQUEST", "8Gi"),
        cpu_request=env_get("SEAT_CPU_REQUEST", "2"),
        kata_memory=env_get("KATA_MEMORY_MIB", "16384"),
        nvidia_caps=env_get(
            "NVIDIA_DRIVER_CAPABILITIES", "compute,utility,graphics,display,video"
        ),
        selkies_encoder=env_get("SELKIES_ENCODER", "nvh264enc"),
        persist_mount=persist_mount,
        role=role,
        orch_url=orch_url,
        https_offset=env_int("SUNSHINE_HTTPS_OFFSET", -5),
        web_offset=env_int("SUNSHINE_WEB_OFFSET", 1),
        rtsp_offset=env_int("SUNSHINE_RTSP_OFFSET", 21),
        udp_offsets=env_csv_ints("SUNSHINE_UDP_OFFSETS", "9,10,11,13,21"),
        proxy_label=env_get("PROXY_NAME", "gs-proxy"),
        orch_label=env_get("ORCH_NAME", "gs-orchestrator"),
        seat_label=env_get("SEAT_APP", "gamestream"),
        advertise=os.environ.get("PROXY_ADVERTISE", ""),
        proxy_cert_publish=cert_publish,
        proxy_cert_host=cert_host,
        proxy_cert_mount=_safe(env_get("PROXY_CERT_MOUNT", "/etc/gamestream/proxy-client.crt"), "PROXY_CERT_MOUNT"),
        proxy_client_name=_safe(env_get("PROXY_CLIENT_NAME", "gs-proxy"), "PROXY_CLIENT_NAME"),
        proxy_cert_required=env_bool("PROXY_CERT_REQUIRED", True),
        sunshine_bind=env_get("SUNSHINE_BIND", "0.0.0.0"),
        sunshine_address_family=env_get("SUNSHINE_ADDRESS_FAMILY", "ipv4"),
        sunshine_origin=env_get("SUNSHINE_ORIGIN_WEB_UI", "lan"),
        sunshine_state_file=env_get("SUNSHINE_STATE_FILE", "sunshine_state.json"),
        sunshine_config_rel=_safe(env_get("SUNSHINE_CONFIG_REL", ".config/sunshine"), "SUNSHINE_CONFIG_REL"),
        selkies_addr=env_get("SELKIES_ADDR", "0.0.0.0"),
        public_http_base=os.environ.get("PUBLIC_HTTP_BASE", ""),
        kata_firmware=kata_firmware,
        kata_firmware_vars=kata_firmware_vars,
        kata_secure_boot=kata_secure_boot,
        tpu_emulation=tpu_emulation,
        tpu_state_dir=tpu_state_dir,
    )


def probe_failures(ready_timeout, period=2):
    """Kubelet checks for the labwc socket this many times.

    period seconds times this count has to cover READY_TIMEOUT. A shorter
    probe marks the seat NotReady while the first layer copy is still running,
    and the orchestrator then reports that the pod never became ready.
    """
    ready = max(int(ready_timeout), period)
    return max(1, (ready + period - 1) // period)


def kata_annotations(cfg, home, activity):
    """What the host shim reads. kernel_params is appended by Kata, and only
    if configuration-nvkvm.toml lists it in enable_annotations. The firmware
    annotation is the OVMF code image; the per-login variable store is the
    sunslop.uefi_vars token, because Kata 4.1 does not pass firmware_volume
    through on a normal guest.
    """
    ann = {
        "io.katacontainers.config.hypervisor.default_vcpus": cfg.cpu_limit,
        "io.katacontainers.config.hypervisor.default_memory": cfg.kata_memory,
        ACTIVITY: activity,
    }
    home = home.rstrip("/")
    params = []
    if cfg.kata_secure_boot:
        ann["io.katacontainers.config.hypervisor.firmware"] = cfg.kata_firmware
        params.append("sunslop.uefi_vars=%s/uefi/OVMF_VARS.fd" % home)
        params.append("sunslop.uefi_code=%s" % cfg.kata_firmware)
    if cfg.tpu_emulation:
        params.append("sunslop.tpu_state=%s/%s" % (home, cfg.tpu_state_dir))
    if params:
        ann["io.katacontainers.config.hypervisor.kernel_params"] = " ".join(params)
    return ann


def seat_pod(cfg, user, gpu, node=None):
    home = cfg.persist_root.rstrip("/") + "/" + user.name
    layer = cfg.layer_host or (cfg.persist_root.rstrip("/") + "/" + cfg.layer_dir)
    wayland = cfg.xdg_runtime.rstrip("/") + "/" + cfg.wayland_display
    node = node or cfg.node
    limits = {"memory": cfg.memory_limit, "cpu": cfg.cpu_limit}
    requests = {"memory": cfg.memory_request, "cpu": cfg.cpu_request}
    if cfg.device_plugin:
        limits["nvidia.com/gpu"] = "1"
        requests["nvidia.com/gpu"] = "1"
    base = cfg.sunshine_base
    udp = ",".join(str(base + off) for off in cfg.udp_offsets)
    env = [
        {"name": "SUNSHINE_BASE_PORT", "value": str(base)},
        {"name": "SUNSHINE_HTTPS_PORT", "value": str(base + cfg.https_offset)},
        {"name": "SUNSHINE_WEB_PORT", "value": str(base + cfg.web_offset)},
        {"name": "SUNSHINE_RTSP_PORT", "value": str(base + cfg.rtsp_offset)},
        {"name": "SUNSHINE_UDP_PORTS", "value": udp},
        {"name": "SUNSHINE_HTTPS_OFFSET", "value": str(cfg.https_offset)},
        {"name": "SUNSHINE_WEB_OFFSET", "value": str(cfg.web_offset)},
        {"name": "SUNSHINE_RTSP_OFFSET", "value": str(cfg.rtsp_offset)},
        {"name": "SUNSHINE_UDP_OFFSETS", "value": ",".join(str(off) for off in cfg.udp_offsets)},
        {"name": "SUNSHINE_BIND", "value": cfg.sunshine_bind},
        {"name": "SUNSHINE_ADDRESS_FAMILY", "value": cfg.sunshine_address_family},
        {"name": "SUNSHINE_ORIGIN_WEB_UI", "value": cfg.sunshine_origin},
        {"name": "SUNSHINE_STATE_FILE", "value": cfg.sunshine_state_file},
        {"name": "SUNSHINE_CONFIG_REL", "value": cfg.sunshine_config_rel},
        {"name": "GS_PROXY_CERT", "value": cfg.proxy_cert_mount},
        {"name": "GS_PROXY_CLIENT_NAME", "value": cfg.proxy_client_name},
        {"name": "GS_PROXY_CERT_REQUIRED", "value": "1" if cfg.proxy_cert_required else "0"},
        {"name": "NVIDIA_VISIBLE_DEVICES", "value": str(gpu)},
        {"name": "NVIDIA_DRIVER_CAPABILITIES", "value": cfg.nvidia_caps},
        {"name": "SELKIES_ENCODER", "value": cfg.selkies_encoder},
        {"name": "SELKIES_PORT", "value": str(cfg.selkies_port)},
        {"name": "SELKIES_ADDR", "value": cfg.selkies_addr},
        {"name": "GS_USER", "value": cfg.seat_user},
        {"name": "GS_UID", "value": str(cfg.seat_uid)},
        {"name": "GS_GID", "value": str(cfg.seat_gid)},
        {"name": "GS_HOME", "value": cfg.seat_home},
        {"name": "GS_LAYER", "value": cfg.layer_mount},
        {"name": "GS_COMMON", "value": cfg.common_mount},
        {"name": "XDG_RUNTIME_DIR", "value": cfg.xdg_runtime},
        {"name": "WAYLAND_DISPLAY", "value": cfg.wayland_display},
    ]
    if cfg.tpu_emulation:
        env.append({"name": "GS_TPU_STATE", "value": cfg.seat_home.rstrip("/") + "/" + cfg.tpu_state_dir})
        env.append({"name": "GS_TPU_DEVICE", "value": "/dev/virtio-ports/org.sunslop.tpu"})
    mounts = [
        {"name": "home", "mountPath": cfg.seat_home},
        {"name": "common", "mountPath": cfg.common_mount},
        {"name": "layer", "mountPath": cfg.layer_mount},
    ]
    volumes = [
        {"name": "home", "hostPath": {"path": home, "type": "DirectoryOrCreate"}},
        {"name": "common", "hostPath": {"path": cfg.common_host, "type": "DirectoryOrCreate"}},
        {"name": "layer", "hostPath": {"path": layer, "type": "DirectoryOrCreate"}},
    ]
    if cfg.proxy_cert_host:
        mounts.append({
            "name": "proxy-cert",
            "mountPath": cfg.proxy_cert_mount,
            "readOnly": True,
        })
        volumes.append({
            "name": "proxy-cert",
            "hostPath": {"path": cfg.proxy_cert_host, "type": "FileOrCreate"},
        })
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": user.pod_name,
            "namespace": cfg.namespace,
            "labels": {
                "app": cfg.seat_label,
                "gamestream.local/user": user.name,
                "gamestream.local/gpu": str(gpu),
            },
            "annotations": kata_annotations(cfg, home, str(int(time.time()))),
        },
        "spec": {
            "restartPolicy": "Never",
            "runtimeClassName": cfg.runtime,
            "nodeName": node,
            "terminationGracePeriodSeconds": 15,
            "containers": [
                {
                    "name": "desktop",
                    "image": cfg.image,
                    "imagePullPolicy": "IfNotPresent",
                    "env": env,
                    "securityContext": {
                        "runAsUser": 0,
                        "capabilities": {"add": ["SYS_ADMIN"]},
                    },
                    "readinessProbe": {
                        "exec": {"command": ["/bin/bash", "-lc", f"test -S {wayland}"]},
                        "initialDelaySeconds": 3,
                        "periodSeconds": 2,
                        "failureThreshold": probe_failures(cfg.ready_timeout),
                    },
                    "resources": {"requests": requests, "limits": limits},
                    "volumeMounts": mounts,
                }
            ],
            "volumes": volumes,
        },
    }


def _read_http_head(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        got = sock.recv(4096)
        if not got:
            break
        data += got
        if len(data) > 1 << 20:
            break
    head, sep, rest = data.partition(b"\r\n\r\n")
    if not sep:
        return data, b""
    return head, rest


def reset(sock):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct_linger())
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def struct_linger():
    import struct
    return struct.pack("ii", 1, 0)


def splice(left, right, touch):
    stop = threading.Event()

    def pump(src, dst):
        try:
            while not stop.is_set():
                data = src.recv(65536)
                if not data:
                    break
                touch()
                dst.sendall(data)
        except OSError:
            pass
        finally:
            stop.set()
            for s, how in ((src, socket.SHUT_RD), (dst, socket.SHUT_WR)):
                try:
                    s.shutdown(how)
                except OSError:
                    pass

    a = threading.Thread(target=pump, args=(left, right), daemon=True)
    b = threading.Thread(target=pump, args=(right, left), daemon=True)
    a.start()
    b.start()
    a.join()
    b.join()


LOGIN_PAGE = """<!doctype html>
<meta charset="utf-8">
<title>gamestream</title>
<style>
body { font: 16px sans-serif; background: #111; color: #eee; }
form { margin: 12vh auto; width: 18rem; display: grid; gap: .6rem; }
input { font: inherit; padding: .4rem; }
button { font: inherit; padding: .4rem; }
.err { color: #f88; }
</style>
<form method="post" action="/login">
<h1>Sign in</h1>
<p class="err">{error}</p>
<label>User <input name="username" autocomplete="username" required></label>
<label>Password <input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit">Continue</button>
</form>
"""

RETRY_PAGE = """<!doctype html>
<meta charset="utf-8">
<meta http-equiv="refresh" content="2">
<title>other node</title>
<p>This seat is on another node. Retrying.</p>
"""


class App:
    def __init__(self, cfg, directory, seats):
        self.cfg = cfg
        self.directory = directory
        self.seats = seats
        self.saml = SamlAuthenticator()
        self.moon = None
        self._udp = {}
        self._udp_lock = threading.Lock()
        self._stop = threading.Event()

    def serve(self):
        if self.cfg.cert_proxy:
            import moonlight_proxy
            self.moon = moonlight_proxy.MoonlightProxy(self.cfg, self.directory, self.seats)
            self.moon.start()
        sel = selectors.DefaultSelector()
        bound = {}
        threading.Thread(target=self._http, name="http", daemon=True).start()
        if self.cfg.role != "proxy":
            threading.Thread(target=self._reap, name="reap", daemon=True).start()
        threading.Thread(target=self._reload, name="reload", daemon=True).start()
        log(f"orchestrator on {self.cfg.node}, http :{self.cfg.http_port}, idle {self.cfg.idle_seconds}s")
        if self.cfg.cert_proxy:
            log("moonlight identity is the client certificate; seats stay on Sunshine's default ports")
            while not self._stop.wait(3600):
                pass
            return
        while not self._stop.is_set():
            self._sync_listeners(sel, bound)
            events = sel.select(timeout=1.0)
            for key, _mask in events:
                kind, port = key.data
                if kind == "tcp":
                    self._accept(key.fileobj, port)
                else:
                    self._udp_in(key.fileobj, port)

    def _reload(self):
        while not self._stop.wait(5):
            self.directory.reload()

    def _reap(self):
        while not self._stop.wait(15):
            try:
                self.seats.reap()
            except Exception as exc:
                log(f"reap: {exc}")

    def _sync_listeners(self, sel, bound):
        want = set(self.directory.by_port)
        for port in list(bound):
            if port not in want:
                for sock in bound.pop(port):
                    try:
                        sel.unregister(sock)
                    except Exception:
                        pass
                    sock.close()
                log(f"unbound {port}")
        for port in sorted(want - set(bound)):
            socks = []
            for proto, kind in ((socket.SOCK_STREAM, "tcp"), (socket.SOCK_DGRAM, "udp")):
                sock = socket.socket(socket.AF_INET, proto)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.bind(("0.0.0.0", port))
                except OSError as exc:
                    log(f"bind {kind} {port}: {exc}")
                    sock.close()
                    continue
                if kind == "tcp":
                    sock.listen(64)
                sock.setblocking(False)
                sel.register(sock, selectors.EVENT_READ, (kind, port))
                socks.append(sock)
            bound[port] = socks
            if socks:
                user = self.directory.by_port[port]
                if port == user.base:
                    log(f"listening {user.name} {port + PORT_LO}-{port + PORT_HI}")

    def _accept(self, listen, port):
        try:
            client, addr = listen.accept()
        except OSError:
            return
        user = self.directory.by_port.get(port)
        threading.Thread(
            target=self._tcp, args=(client, addr, port, user), daemon=True
        ).start()

    def _tcp(self, client, addr, port, user):
        back = None
        try:
            client.settimeout(self.cfg.ready_timeout + 30)
            if user is None:
                reset(client)
                return
            kind, info = self.seats.ensure(user)
            if kind != "local":
                log(f"{user.name}: reject tcp {addr[0]}:{port} ({kind} {info})")
                reset(client)
                return
            back = socket.create_connection((info, pod_port(port, user.base, self.cfg.sunshine_base)), timeout=10)
            client.settimeout(None)
            back.settimeout(None)
            splice(client, back, lambda: self.seats.touch(user.name))
        except OSError as exc:
            log(f"tcp {port}: {exc}")
        finally:
            for sock in (client, back):
                if sock is None:
                    continue
                try:
                    sock.close()
                except OSError:
                    pass

    def _udp_in(self, sock, port):
        try:
            data, addr = sock.recvfrom(65535)
        except OSError:
            return
        user = self.directory.by_port.get(port)
        if user is None:
            return
        threading.Thread(
            target=self._udp_handle, args=(sock, port, user, data, addr), daemon=True
        ).start()

    def _udp_handle(self, sock, port, user, data, addr):
        with self._udp_lock:
            state = self._udp.setdefault(port, {})
            pod = state.get("pod")
        if pod and addr[0] == pod:
            client = state.get("client")
            if client:
                try:
                    sock.sendto(data, client)
                    self.seats.touch(user.name)
                except OSError:
                    pass
            return
        kind, info = self.seats.ensure(user)
        if kind != "local":
            return
        with self._udp_lock:
            state = self._udp.setdefault(port, {})
            state["client"] = addr
            state["pod"] = info
        try:
            sock.sendto(data, (info, pod_port(port, user.base, self.cfg.sunshine_base)))
            self.seats.touch(user.name)
        except OSError as exc:
            log(f"udp {port}: {exc}")

    def _http(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        app = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                log("http " + (fmt % args))

            def do_HEAD(self):
                self._dispatch()

            def do_GET(self):
                self._dispatch()

            def do_POST(self):
                self._dispatch()

            def do_PUT(self):
                self._dispatch()

            def do_DELETE(self):
                self._dispatch()

            def _dispatch(self):
                path = urllib.parse.urlsplit(self.path).path
                if path == "/admin" or path.startswith("/admin/"):
                    if app.moon is None:
                        self._page(404, "certificate proxy is off\n", "text/plain")
                        return
                    app.moon.handle_admin(self)
                    return
                if path == "/login" and self.command == "POST":
                    self._login()
                    return
                if path == "/login":
                    self._page(200, LOGIN_PAGE.format(error=""))
                    return
                if path == "/saml/acs":
                    self._saml()
                    return
                if path == "/healthz":
                    self._page(200, "ok\n", "text/plain")
                    return
                user = self._session_user()
                if user is None:
                    self._page(401, LOGIN_PAGE.format(error=""))
                    return
                self._open_seat(user)

            def _session_user(self):
                token = ""
                raw = self.headers.get("Cookie", "")
                for part in raw.split(";"):
                    part = part.strip()
                    if part.startswith("gs_session="):
                        token = urllib.parse.unquote(part.split("=", 1)[1])
                name = read_token(token, app.cfg.secret)
                if not name:
                    return None
                return app.directory.get(name)

            def _login(self):
                length = int(self.headers.get("Content-Length", "0") or "0")
                if length > 4096:
                    self._page(400, "no\n", "text/plain")
                    return
                form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
                username = (form.get("username") or [""])[0]
                password = (form.get("password") or [""])[0]
                user = app.directory.authenticate(username, password)
                if user is None:
                    self._page(401, LOGIN_PAGE.format(error="Unknown user or password."))
                    return
                self.send_response(302)
                self._send_cookie(user.name)
                self.send_header("Location", "/")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _saml(self):
                length = int(self.headers.get("Content-Length", "0") or "0")
                payload = self.rfile.read(min(length, 1 << 20)) if length else b""
                try:
                    name = app.saml.consume(payload)
                except NotImplementedError:
                    self._page(501, "SAML is not configured\n", "text/plain")
                    return
                if app.directory.get(name) is None:
                    self._page(403, "authenticated but no seat\n", "text/plain")
                    return
                self.send_response(302)
                self._send_cookie(name)
                self.send_header("Location", "/")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _send_cookie(self, username):
                token = issue_token(username, app.cfg.secret, app.cfg.cookie_ttl)
                flags = f"gs_session={urllib.parse.quote(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age={app.cfg.cookie_ttl}"
                if (self.headers.get("X-Forwarded-Proto") or "").lower() == "https":
                    flags += "; Secure"
                self.send_header("Set-Cookie", flags)

            def _page(self, code, body, content_type="text/html; charset=utf-8"):
                data = body.encode()
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data)

            def _open_seat(self, user):
                placed = app.seats.ensure(user)
                kind, info = placed.kind, placed.info
                if kind == "local" or (kind == "remote" and app.cfg.http_foreign == "proxy" and info):
                    try:
                        self._proxy(user, info)
                    except OSError as exc:
                        log(f"{user.name}: selkies proxy {exc}")
                        try:
                            self._page(502, "backend closed\n", "text/plain")
                        except OSError:
                            pass
                    return
                if kind == "remote":
                    self._redirect_proxy(placed)
                    return
                if kind == "foreign":
                    self._foreign(info)
                    return
                self._page(503, f"seat unavailable: {info}\n", "text/plain")

            def _redirect_proxy(self, placed):
                host = placed.proxy_host
                if app.cfg.http_foreign == "reset" or not host:
                    self.close_connection = True
                    self._page(503, RETRY_PAGE)
                    return
                loc = public_base(app.cfg, host) + self.path
                self.send_response(307)
                self.send_header("Location", loc)
                self.send_header("Content-Length", "0")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()

            def _foreign(self, node):
                if app.cfg.http_foreign != "proxy" or self.headers.get("X-GS-Hop"):
                    self._page(503, RETRY_PAGE)
                    return
                url = app.seats.owner_url(node)
                if not url:
                    self._page(503, RETRY_PAGE)
                    return
                self._proxy_orchestrator(url)

            def _proxy(self, user, ip):
                self._stream(user, (ip, app.cfg.selkies_port), hop=False)

            def _proxy_orchestrator(self, url):
                parsed = urllib.parse.urlsplit(url)
                self._stream(None, (parsed.hostname, parsed.port), hop=True)

            def _stream(self, user, dest, hop):
                self.close_connection = True
                back = socket.create_connection(dest, timeout=20)
                upgrade = (self.headers.get("Upgrade") or "").lower() == "websocket"
                lines = [f"{self.command} {self.path} HTTP/1.1"]
                for key, value in self.headers.items():
                    if key.lower() in HOP and not (upgrade and key.lower() in ("connection", "upgrade")):
                        continue
                    lines.append(f"{key}: {value}")
                if hop:
                    lines.append("X-GS-Hop: 1")
                if not upgrade:
                    lines.append("Connection: close")
                raw = ("\r\n".join(lines) + "\r\n\r\n").encode()
                back.sendall(raw)
                length = int(self.headers.get("Content-Length", "0") or "0")
                if length and self.command not in ("GET", "HEAD"):
                    remaining = length
                    while remaining:
                        chunk = self.rfile.read(min(65536, remaining))
                        if not chunk:
                            break
                        back.sendall(chunk)
                        remaining -= len(chunk)
                head, rest = _read_http_head(back)
                if user is not None and head:
                    head = head + b"\r\n" + self._cookie_line(user.name)
                self.wfile.write(head + b"\r\n\r\n" + rest)
                self.wfile.flush()
                if upgrade:
                    touch = (lambda: app.seats.touch(user.name)) if user is not None else (lambda: None)
                    splice(self.connection, back, touch)
                    return
                while True:
                    chunk = back.recv(65536)
                    if not chunk:
                        break
                    if user is not None:
                        app.seats.touch(user.name)
                    self.wfile.write(chunk)
                back.close()

            def _cookie_line(self, username):
                token = issue_token(username, app.cfg.secret, app.cfg.cookie_ttl)
                flags = (
                    f"gs_session={urllib.parse.quote(token)}; HttpOnly; Path=/; "
                    f"SameSite=Lax; Max-Age={app.cfg.cookie_ttl}"
                )
                if (self.headers.get("X-Forwarded-Proto") or "").lower() == "https":
                    flags += "; Secure"
                return f"Set-Cookie: {flags}".encode()

        ThreadingHTTPServer.allow_reuse_address = True
        server = ThreadingHTTPServer(("0.0.0.0", app.cfg.http_port), Handler)
        server.serve_forever()


class RemoteSeats:
    """Proxy-side view. The orchestrator owns create, delete, and placement."""

    def __init__(self, cfg):
        self.cfg = cfg
        self._patched = {}
        self._guard = threading.Lock()

    def touch(self, name):
        now = time.monotonic()
        with self._guard:
            if now - self._patched.get(name, 0) < 30:
                return
            self._patched[name] = now
        threading.Thread(target=self._touch, args=(name,), daemon=True).start()

    def _touch(self, name):
        try:
            self._call("POST", "/v1/touch", {"user": name})
        except Exception as exc:
            log(f"{name}: touch {exc}")

    def lookup(self, user):
        if user is None:
            return None
        try:
            data = self._call("POST", "/v1/lookup", {"user": user.name, "preferNode": self.cfg.node})
        except Exception as exc:
            log(f"{user.name}: lookup {exc}")
            return None
        if not data or data.get("kind") in (None, "down", "missing"):
            return None
        return place_from_api(data)

    def ensure(self, user):
        data = self._call(
            "POST",
            "/v1/ensure",
            {"user": user.name, "preferNode": self.cfg.node},
            timeout=self.cfg.ready_timeout + 60,
        )
        return place_from_api(data)

    def owner_url(self, node):
        try:
            data = self._call("POST", "/v1/owner", {"node": node})
        except Exception:
            return None
        return data.get("url") or None

    def _call(self, method, path, body, timeout=30):
        url = self.cfg.orch_url.rstrip("/") + path
        req = urllib.request.Request(url, data=json.dumps(body).encode(), method=method)
        req.add_header("Authorization", "Bearer " + api_token(self.cfg.secret))
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            raise RuntimeError(f"{exc.code} {raw[:200]!r}") from exc


class OrchestratorApi:
    def __init__(self, cfg, directory, seats):
        self.cfg = cfg
        self.directory = directory
        self.seats = seats

    def serve(self):
        publish_proxy_cert(self.cfg)
        threading.Thread(target=self._reap, name="reap", daemon=True).start()
        threading.Thread(target=self._reload, name="reload", daemon=True).start()
        log(f"orchestrator api on :{self.cfg.http_port}, idle {self.cfg.idle_seconds}s")
        self._http()

    def _reap(self):
        while True:
            time.sleep(15)
            try:
                self.seats.reap()
            except Exception as exc:
                log(f"reap: {exc}")

    def _reload(self):
        while True:
            time.sleep(5)
            self.directory.reload()

    def _http(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        api = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                log("api " + (fmt % args))

            def do_GET(self):
                self._dispatch()

            def do_POST(self):
                self._dispatch()

            def _dispatch(self):
                path = urllib.parse.urlsplit(self.path).path
                if path == "/healthz":
                    self._json(200, {"ok": True})
                    return
                if not path.startswith("/v1/"):
                    self._json(404, {"kind": "error", "detail": "not found"})
                    return
                if not self._auth():
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0") or "0")
                    raw = self.rfile.read(min(length, 1 << 16)) if length else b"{}"
                    body = json.loads(raw.decode() or "{}")
                except (ValueError, json.JSONDecodeError):
                    self._json(400, {"kind": "error", "detail": "bad json"})
                    return
                try:
                    if path == "/v1/ensure":
                        self._ensure(body)
                    elif path == "/v1/lookup":
                        self._lookup(body)
                    elif path == "/v1/touch":
                        api.seats.touch(body.get("user") or "")
                        self._json(200, {"ok": True})
                    elif path == "/v1/owner":
                        url = api.seats.owner_url(body.get("node") or "")
                        self._json(200, {"url": url or ""})
                    else:
                        self._json(404, {"kind": "error", "detail": "not found"})
                except Exception as exc:
                    log(f"api {path}: {exc}")
                    self._json(500, {"kind": "error", "detail": str(exc)[:300]})

            def _auth(self):
                expect = "Bearer " + api_token(api.cfg.secret)
                got = self.headers.get("Authorization") or ""
                if len(got) == len(expect) and hmac.compare_digest(got, expect):
                    return True
                self._json(401, {"kind": "error", "detail": "unauthorized"})
                return False

            def _user(self, body):
                name = body.get("user") or ""
                user = api.directory.get(name)
                if user is None:
                    self._json(404, {"kind": "error", "detail": "unknown user"})
                return user

            def _ensure(self, body):
                user = self._user(body)
                if user is None:
                    return
                prefer = body.get("preferNode") or api.cfg.node
                self._json(200, place_dict(api.seats.ensure(user, prefer_node=prefer)))

            def _lookup(self, body):
                user = self._user(body)
                if user is None:
                    return
                prefer = body.get("preferNode") or api.cfg.node
                placed = api.seats.lookup(user, prefer)
                if placed is None:
                    self._json(200, {"kind": "down"})
                    return
                self._json(200, place_dict(placed))

            def _json(self, code, payload):
                raw = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(raw)

        ThreadingHTTPServer.allow_reuse_address = True
        server = ThreadingHTTPServer(("0.0.0.0", api.cfg.http_port), Handler)
        server.serve_forever()


def require_persist_mount(path):
    """The certificate store has to be the shared disk, not a local directory.

    A hostPath that was never mounted shows up as a subdirectory of `/`.
    Starting anyway creates a second certificate that the other node will
    not trust. GS_PERSIST_ALLOW_UNMOUNTED=1 is only for a local run.
    """
    if os.environ.get("GS_PERSIST_ALLOW_UNMOUNTED", "") == "1":
        log(f"persist: {path} mount check skipped")
        return
    real = os.path.realpath(path)
    best = None
    try:
        mounts = open("/proc/mounts")
    except OSError as exc:
        raise SystemExit(f"persist: cannot read mounts: {exc}") from exc
    with mounts:
        for line in mounts:
            parts = line.split()
            if len(parts) < 3:
                continue
            mnt = os.path.realpath(parts[1].replace("\\040", " "))
            if real == mnt or real.startswith(mnt.rstrip("/") + "/"):
                if best is None or len(mnt) > len(best[0]):
                    best = (mnt, parts[0], parts[2])
    if best is None or best[0] != real:
        raise SystemExit(
            f"{path} is not a mount. Refusing to start, because a local directory "
            "would mint a second certificate. The pod must mount the shared "
            "PERSIST_ROOT at this path. GS_PERSIST_ALLOW_UNMOUNTED=1 is only for a local run."
        )
    marker = os.path.join(real, ".sunslop-volume")
    if not os.path.isfile(marker):
        raise SystemExit(
            f"{marker} is missing. On the shared filesystem, run "
            "`touch <PERSIST_ROOT>/.sunslop-volume` once, and confirm every "
            "proxy node and the orchestrator node see that same file. "
            "A node-local directory would mint a second certificate."
        )
    log(f"persist: {path} is {best[1]} ({best[2]})")


def publish_proxy_cert(cfg):
    import moonlight_proxy
    moonlight_proxy.Store(cfg.proxy_store, cert_path=cfg.proxy_cert_publish or None)


def self_test():
    users = load_users(
        "# c\ngsuser0,secret,47989\ngsuser1,other,48089\n"
    )
    assert set(users) == {"gsuser0", "gsuser1"}
    assert list(port_span(47989))[0] == 47984
    assert list(port_span(47989))[-1] == 48010
    assert len(list(port_span(47989))) == SPAN
    try:
        load_users("gsuser0,a,47989\ngsuser1,b,48000\n")
        raise SystemExit("overlap accepted")
    except ValueError:
        pass
    try:
        load_users("common,a,47989\n")
        raise SystemExit("common accepted")
    except ValueError:
        pass
    try:
        load_users("proxy,a,47989\n")
        raise SystemExit("proxy accepted")
    except ValueError:
        pass
    try:
        load_users("gs-layer,a,47989\n")
        raise SystemExit("gs-layer accepted")
    except ValueError:
        pass
    try:
        load_users("library,a,47989\n", reserved_names("library"))
        raise SystemExit("configured dir accepted as a login")
    except ValueError:
        pass
    try:
        load_users("gsuser0,CHANGE_ME_selkies_password,47989\n")
        raise SystemExit("placeholder password accepted")
    except ValueError:
        pass
    assert probe_failures(900) == 450
    assert probe_failures(901) == 451
    secret = b"0123456789abcdef"
    tok = issue_token("gsuser0", secret, 100, now=1_000)
    assert read_token(tok, secret, now=1_050) == "gsuser0"
    assert read_token(tok, secret, now=1_200) is None
    assert read_token(tok, b"0123456789abcdee", now=1_050) is None
    assert pick_gpu([0, 0, 1], 2, 8) == 1
    assert pick_gpu([], 2, 8) == 0
    assert pick_gpu([0] * 8 + [1] * 8, 2, 8) is None
    assert pick_gpu([0] * 8, 2, 8) == 1
    assert still_active(10, 1000, 600)
    assert still_active(1000, 10, 600)
    assert not still_active(1000, 1000, 600)
    assert not still_active(1000, None, 600)
    assert still_active(None, None, 600)
    cfg = Config(
        node="n1", namespace="ns", users_file="", secret=secret, cookie_ttl=10,
        idle_seconds=600, persist_root="/data/persist",
        common_host="/data/persist/common",
        common_mount="/games", image="gamestream:local", runtime="nvkvm-kata",
        gpu_count=2, sessions_per_gpu=8, http_port=8080, selkies_port=8082,
        ready_timeout=180, device_plugin=True, http_foreign="proxy",
        memory_limit="16Gi", cpu_limit="8",
    )
    assert cfg.cert_proxy is True
    common, layer, store, cert_pub, cert_host = derive_storage(
        "/data/persist", "common", "gs-layer", "proxy", "/var/lib/gs-persist"
    )
    assert common == "/data/persist/common"
    assert layer == "/data/persist/gs-layer"
    assert store == "/var/lib/gs-persist/proxy/store.json"
    assert cert_pub == "/var/lib/gs-persist/proxy/proxy-client.crt"
    assert cert_host == "/data/persist/proxy/proxy-client.crt"
    assert "cs1-resident" not in derive_storage(
        "/var/lib/gamestream/persistent", "common", "gs-layer", "proxy", "/var/lib/gs-persist"
    )[0]
    pod = seat_pod(cfg, users["gsuser0"], 1)
    assert pod["spec"]["volumes"][0]["hostPath"]["path"].endswith("/gsuser0")
    assert pod["spec"]["volumes"][1]["hostPath"]["path"].endswith("/common")
    assert pod["spec"]["nodeName"] == "n1"
    assert pod["metadata"]["labels"]["gamestream.local/gpu"] == "1"
    assert pod["metadata"]["annotations"][ACTIVITY].isdigit()
    ann = pod["metadata"]["annotations"]
    assert ann["io.katacontainers.config.hypervisor.firmware"].endswith("OVMF_CODE.secboot.fd")
    boot = ann["io.katacontainers.config.hypervisor.kernel_params"]
    assert "sunslop.tpu_state=/data/persist/gsuser0/tpu" in boot
    assert "sunslop.uefi_vars=/data/persist/gsuser0/uefi/OVMF_VARS.fd" in boot
    assert ".." not in boot
    cfg.tpu_emulation = False
    cfg.kata_secure_boot = False
    quiet = seat_pod(cfg, users["gsuser0"], 1)
    qann = quiet["metadata"]["annotations"]
    assert "io.katacontainers.config.hypervisor.firmware" not in qann
    assert "io.katacontainers.config.hypervisor.kernel_params" not in qann
    qenv = {item["name"]: item["value"] for item in quiet["spec"]["containers"][0]["env"]}
    assert "GS_TPU_STATE" not in qenv
    cfg.tpu_emulation = True
    cfg.kata_secure_boot = True
    assert pod_port(48089, 48089) == 47989
    assert pod_port(48084, 48089) == 47984
    assert pod_port(48098, 48089) == 47998
    assert pod_port(48110, 48089) == 48010
    pod = seat_pod(cfg, users["gsuser1"], 1)
    assert pod["spec"]["containers"][0]["env"][0]["value"] == "47989"
    env = {item["name"]: item["value"] for item in pod["spec"]["containers"][0]["env"]}
    assert env["GS_LAYER"] == "/gs-layer"
    assert env["GS_HOME"] == "/home/gsuser"
    assert env["GS_USER"] == "gsuser"
    assert env["GS_TPU_STATE"] == "/home/gsuser/tpu"
    assert env["GS_TPU_DEVICE"] == "/dev/virtio-ports/org.sunslop.tpu"
    assert pod["spec"]["volumes"][2]["hostPath"]["path"].endswith("/gs-layer")
    probe = pod["spec"]["containers"][0]["readinessProbe"]["exec"]["command"][-1]
    assert probe == "test -S /run/user/1000/wayland-0"
    custom = Config(
        node="n1", namespace="ns", users_file="", secret=secret, cookie_ttl=10,
        idle_seconds=600, persist_root="/data/persist",
        common_host="/data/persist/library",
        common_mount="/library", image="seat:custom", runtime="kata-custom",
        gpu_count=2, sessions_per_gpu=8, http_port=8080, selkies_port=9090,
        ready_timeout=180, device_plugin=True, http_foreign="proxy",
        memory_limit="16Gi", cpu_limit="8",
        layer_dir="packages", layer_host="/data/persist/packages", layer_mount="/packages",
        seat_user="player", seat_uid=2000, seat_gid=2000, seat_home="/home/player",
        xdg_runtime="/run/user/2000", wayland_display="wayland-1", sunshine_base=48000,
        memory_request="4Gi", cpu_request="1", kata_memory="8192",
    )
    pod = seat_pod(custom, users["gsuser0"], 0)
    env = {item["name"]: item["value"] for item in pod["spec"]["containers"][0]["env"]}
    assert env["SUNSHINE_BASE_PORT"] == "48000"
    assert env["GS_USER"] == "player"
    assert env["GS_UID"] == "2000"
    assert env["GS_HOME"] == "/home/player"
    assert env["GS_LAYER"] == "/packages"
    assert env["SELKIES_PORT"] == "9090"
    assert pod["spec"]["volumes"][2]["hostPath"]["path"] == "/data/persist/packages"
    assert pod["spec"]["containers"][0]["volumeMounts"][0]["mountPath"] == "/home/player"
    assert pod["spec"]["containers"][0]["readinessProbe"]["exec"]["command"][-1] == "test -S /run/user/2000/wayland-1"
    assert pod["metadata"]["annotations"]["io.katacontainers.config.hypervisor.default_memory"] == "8192"
    assert pod["spec"]["containers"][0]["resources"]["requests"]["memory"] == "4Gi"
    assert public_base(cfg, "10.1.1.9") == "http://10.1.1.9:8080"
    nodes = {"b": "2.2.2.2", "a": "1.1.1.1"}
    assert pick_node("a", nodes, lambda n: True) == ("a", "1.1.1.1")
    assert pick_node("a", nodes, lambda n: n != "a") == ("b", "2.2.2.2")
    assert pick_node("a", nodes, lambda n: False) == (None, "")
    kind, info = Place("local", "10.0.0.5", "1.2.3.4", "n1")
    assert kind == "local" and info == "10.0.0.5"
    assert "host" not in HOP
    _component_test()
    print("self-test ok")


def _component_test():
    """Proxy API, placement, Selkies login, and the foreign-seat redirect."""
    import tempfile
    users_file = os.path.join(tempfile.mkdtemp(), "users.csv")
    open(users_file, "w").write("gsuser0,secret,47989\ngsuser1,other,48089\n")
    directory = Directory(users_file, reserved_names("common", "gs-layer", "proxy"))
    secret = b"0123456789abcdef"

    def front(node, ip):
        return {
            "metadata": {"name": "proxy-" + node, "labels": {"app": "gs-proxy"}, "annotations": {}},
            "spec": {"nodeName": node},
            "status": {"phase": "Running", "hostIP": ip},
        }

    class Kube:
        def __init__(self):
            self.pods = {}
            self.fronts = [front("node-a", "4.4.4.3"), front("node-b", "4.4.4.4")]

        def get_pod(self, name):
            return self.pods.get(name)

        def create_pod(self, body):
            pod = json.loads(json.dumps(body))
            pod["status"] = {
                "phase": "Running",
                "podIP": "10.8.0." + str(8 + len(self.pods)),
                "hostIP": "10.0.0.1",
                "conditions": [{"type": "Ready", "status": "True"}],
            }
            self.pods[pod["metadata"]["name"]] = pod
            return 201, pod

        def delete_pod(self, name):
            self.pods.pop(name, None)
            return 200, {}

        def patch_pod(self, name, body):
            pod = self.pods.get(name)
            if pod is None:
                return 404, {}
            ann = ((body.get("metadata") or {}).get("annotations") or {})
            pod.setdefault("metadata", {}).setdefault("annotations", {}).update(ann)
            return 200, pod

        def list_seats(self):
            return list(self.pods.values())

        def list_apps(self, _names):
            return self.fronts

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    api_port = probe.getsockname()[1]
    probe.close()
    cfg = Config(
        node="orch", namespace="gamestream", users_file=users_file, secret=secret,
        cookie_ttl=100, idle_seconds=600, persist_root="/data/persist",
        common_host="/data/persist/common", common_mount="/games",
        image="gamestream:local", runtime="nvkvm-kata", gpu_count=2,
        sessions_per_gpu=8, http_port=api_port, selkies_port=8082,
        ready_timeout=5, device_plugin=True, http_foreign="redirect",
        memory_limit="16Gi", cpu_limit="8", role="orchestrator",
        proxy_label="gs-proxy", orch_label="gs-orchestrator",
    )
    kube = Kube()
    for i in range(8):
        for gpu in (0, 1):
            name = f"busy-{gpu}-{i}"
            kube.pods[name] = {
                "metadata": {
                    "name": name,
                    "labels": {
                        "gamestream.local/user": name,
                        "gamestream.local/gpu": str(gpu),
                    },
                    "annotations": {},
                },
                "spec": {"nodeName": "node-a"},
                "status": {"phase": "Running", "podIP": "10.1.0.1"},
            }
    seats = Seats(cfg, directory, kube)
    threading.Thread(target=OrchestratorApi(cfg, directory, seats)._http, daemon=True).start()
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", api_port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    else:
        raise SystemExit("orchestrator api did not listen")
    bad = urllib.request.Request(
        f"http://127.0.0.1:{api_port}/v1/ensure", data=b"{}", method="POST",
    )
    bad.add_header("Authorization", "Bearer nope")
    bad.add_header("Content-Type", "application/json")
    try:
        urllib.request.urlopen(bad, timeout=3)
        raise SystemExit("api accepted a bad token")
    except urllib.error.HTTPError as exc:
        assert exc.code == 401
    proxy_cfg = Config(
        node="node-a", namespace="gamestream", users_file=users_file, secret=secret,
        cookie_ttl=100, idle_seconds=600, persist_root="/data/persist",
        common_host="/data/persist/common", common_mount="/games",
        image="gamestream:local", runtime="nvkvm-kata", gpu_count=2,
        sessions_per_gpu=8, http_port=api_port, selkies_port=8082,
        ready_timeout=5, device_plugin=True, http_foreign="redirect",
        memory_limit="16Gi", cpu_limit="8", role="proxy",
        orch_url=f"http://127.0.0.1:{api_port}",
        proxy_label="gs-proxy", public_http_base="https://{host}",
    )
    remote = RemoteSeats(proxy_cfg)
    spilled = remote.ensure(directory.get("gsuser1"))
    assert spilled.kind == "remote", spilled.kind
    assert spilled.proxy_host == "4.4.4.4"
    assert spilled.node == "node-b"
    assert spilled.info == ""
    for pod in list(kube.pods):
        if pod.startswith("busy-"):
            kube.pods.pop(pod)
    # node-a is the proxy asking, and it has room now. A new login lands there.
    home = remote.ensure(directory.get("gsuser0"))
    assert home.kind == "local", home.kind
    assert home.node == "node-a"
    assert home.info.startswith("10.8.0.")
    time.sleep(0.4)
    seats.activity["gsuser0"] = time.monotonic() - 5000
    kube.pods["gs-gsuser0"]["metadata"]["annotations"][ACTIVITY] = str(int(time.time()) - 5000)
    seats.reap()
    assert "gs-gsuser0" not in kube.pods

    echo_box = {}

    def echo():
        listen = socket.socket()
        listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen.bind(("127.0.0.1", 0))
        listen.listen(4)
        echo_box["port"] = listen.getsockname()[1]
        echo_box["ready"].set()
        while True:
            conn, _addr = listen.accept()
            data = b""
            conn.settimeout(3)
            try:
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                conn.close()
                continue
            echo_box["req"] = data
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            conn.close()

    echo_box["ready"] = threading.Event()
    threading.Thread(target=echo, daemon=True).start()
    assert echo_box["ready"].wait(3)
    web = socket.socket()
    web.bind(("127.0.0.1", 0))
    web_port = web.getsockname()[1]
    web.close()

    class WebSeats:
        def __init__(self):
            self.place = Place("local", "127.0.0.1", "4.4.4.4", "node-a")

        def ensure(self, user):
            return self.place

        def touch(self, name):
            return None

        def lookup(self, user):
            return self.place

    web_cfg = Config(
        node="node-a", namespace="gamestream", users_file=users_file, secret=secret,
        cookie_ttl=100, idle_seconds=600, persist_root="/data/persist",
        common_host="/data/persist/common", common_mount="/games",
        image="gamestream:local", runtime="nvkvm-kata", gpu_count=2,
        sessions_per_gpu=8, http_port=web_port, selkies_port=echo_box["port"],
        ready_timeout=5, device_plugin=False, http_foreign="redirect",
        memory_limit="16Gi", cpu_limit="8", cert_proxy=False,
        public_http_base="https://{host}",
    )
    web_seats = WebSeats()
    threading.Thread(target=App(web_cfg, directory, web_seats)._http, daemon=True).start()
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", web_port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    else:
        raise SystemExit("selkies http did not listen")

    def raw_http(port, payload):
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        sock.settimeout(5)
        sock.sendall(payload)
        head, rest = _read_http_head(sock)
        length = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":", 1)[1].strip())
        while len(rest) < length:
            chunk = sock.recv(4096)
            if not chunk:
                break
            rest += chunk
        sock.close()
        return head + b"\r\n\r\n" + rest[:length]

    login = raw_http(
        web_port,
        b"POST /login HTTP/1.1\r\nHost: gs.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 32\r\nConnection: close\r\n\r\n"
        b"username=gsuser0&password=secret",
    )
    assert b" 302 " in login.split(b"\r\n", 1)[0]
    cookie = b""
    for line in login.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:"):
            cookie = line.split(b":", 1)[1].strip().split(b";", 1)[0]
    assert cookie.startswith(b"gs_session=")
    page = raw_http(
        web_port,
        b"GET /play HTTP/1.1\r\nHost: gs.example\r\nCookie: " + cookie + b"\r\nConnection: close\r\n\r\n",
    )
    assert b"Host: gs.example" in echo_box["req"]
    assert b"200" in page.split(b"\r\n", 1)[0]
    web_seats.place = Place("remote", "", "4.4.4.4", "node-b")
    moved = raw_http(
        web_port,
        b"GET /play HTTP/1.1\r\nHost: gs.example\r\nCookie: " + cookie + b"\r\nConnection: close\r\n\r\n",
    )
    status = moved.split(b"\r\n", 1)[0]
    assert b" 307 " in status, status
    assert b"Location: https://4.4.4.4/play" in moved


def main():
    if "--self-test" in sys.argv:
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



