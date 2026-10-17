"""Logins, session cookies, and where a seat was placed."""
import base64
import hashlib
import hmac
import os
import time
from dataclasses import dataclass

PORT_LO = -5   # 47984 HTTPS when the external base is 47989
PORT_HI = 21   # 48010 RTSP / trailing UDP
SPAN = PORT_HI - PORT_LO + 1  # 27
SUNSHINE_BASE = 47989  # every seat listens here, whatever the client dialed
ACTIVITY = "gamestream.local/last-activity"
ADVERTISE = "gamestream.local/advertise"


def _address(value):
    """First address, without a CIDR prefix. Kube-OVN writes both forms."""
    raw = (value or "").strip()
    if not raw:
        return ""
    raw = raw.split(",")[0].strip()
    return raw.split("/")[0].strip()


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


def advertise_host(pod, front_network="", front_ns=""):
    """Address clients should dial for this proxy.

    A manual gamestream.local/advertise wins. Otherwise the kube-ovn
    address on the front attachment (cs1-resident) is the one Moonlight
    can reach. The node hostIP is only the fallback when no front
    network is configured, which is a hostNetwork pod.
    """
    ann = ((pod.get("metadata") or {}).get("annotations") or {})
    stamped = _address(ann.get(ADVERTISE) or "")
    if stamped:
        return stamped
    network = (front_network or "").strip()
    ns = (front_ns or "").strip()
    if network and ns:
        key = "%s.%s.ovn.kubernetes.io/ip_address" % (network, ns)
        return _address(ann.get(key) or "")
    return _address(((pod.get("status") or {}).get("hostIP") or ""))


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
    games: str = "unique"

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
    """username,password,base_port[,games]. '#' comments. No commas in fields.

    games is common or unique. Omitted means unique: the seat does not
    mount /games or /gamessd. common uses the host paths from GAMES_HOST
    and GAMESSD_HOST.
    """
    users = {}
    taken = []
    blocked = reserved_names() if reserved is None else set(reserved)
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) not in (3, 4):
            raise ValueError(f"{lineno}: want username,password,base_port[,games]")
        name, password, base_s = parts[:3]
        games = parts[3].lower() if len(parts) == 4 and parts[3] else "unique"
        if games not in ("common", "unique"):
            raise ValueError(f"{lineno}: games must be common or unique")
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
        users[name] = User(name, password, base, games)
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

