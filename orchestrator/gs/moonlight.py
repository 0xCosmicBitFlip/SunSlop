"""TLS front end, plain-HTTP pairing port, and /admin."""
import hmac
import json
import os
import socket
import ssl
import threading
import time
import urllib.parse
from hashlib import sha256

from gs.pairing import PairServer
from gs.protocol import (
    HTTPS_OFFSET,
    PIN_WAIT,
    RTSP_OFFSET,
    SUNSHINE_HTTP,
    UDP_OFFSETS,
    WEB_OFFSET,
    _sock_ip,
    _write_temp,
    facing_host,
    fail_xml,
    fingerprint,
    log,
    moonlight_foreign,
    ports_for,
    read_http,
    read_response,
    reset_tcp,
    rewrite_backend_response,
    serverinfo_xml,
    xml_response,
)
from gs.relay import RustRelay
from gs.store import Store, state_has_cert

class MoonlightProxy:
    def __init__(self, cfg, directory, seats):
        self.cfg = cfg
        self.directory = directory
        self.seats = seats
        cert_path = getattr(cfg, "proxy_cert_publish", "") or None
        self.store = Store(cfg.proxy_store, cert_path=cert_path)
        self.ports = ports_for(
            getattr(cfg, "sunshine_base", SUNSHINE_HTTP),
            https_offset=getattr(cfg, "https_offset", HTTPS_OFFSET),
            web_offset=getattr(cfg, "web_offset", WEB_OFFSET),
            rtsp_offset=getattr(cfg, "rtsp_offset", RTSP_OFFSET),
            udp_offsets=getattr(cfg, "udp_offsets", UDP_OFFSETS),
        )
        self.pairs = PairServer(self.store)
        self.by_ip = {}
        self._pointed = set()
        self._map_lock = threading.Lock()
        self._stop = threading.Event()
        self._tls_ctx = None
        self._trust_lock = threading.Lock()
        self._trusted = None

    def _refresh_trust(self):
        """Trust paired client certs so the TLS handshake can finish.

        Moonlight's cert is self-signed. CERT_OPTIONAL still verifies a
        presented cert, and Python rejects it with no matching trust
        anchor, before we can read it. Loading the paired PEMs makes
        that handshake succeed. An unknown cert still fails the
        handshake; HTTP serverinfo remains the unpaired poll.
        """
        with self._trust_lock:
            ctx = self._tls_ctx
            clients = (self.store.snapshot().get("clients") or [])
            fps = tuple(sorted(c.get("fingerprint") or "" for c in clients))
            if ctx is None or fps == self._trusted:
                return
            pems = []
            for client in clients:
                cert = client.get("cert") or ""
                if "BEGIN CERTIFICATE" not in cert:
                    continue
                pems.append(cert if str(cert).endswith("\n") else str(cert) + "\n")
            if pems:
                try:
                    ctx.load_verify_locations(cadata="".join(pems))
                except ssl.SSLError as exc:
                    log(f"client trust: {exc}")
                    return
            self._trusted = fps
            if pems:
                log(f"trusting {len(pems)} moonlight client certificate(s)")

    def start(self):
        wait = max(30, int(getattr(self.cfg, "ready_timeout", 30) or 30))
        bind = getattr(self.cfg, "relay_bind", "") or "0.0.0.0"
        self.relay = RustRelay(self.ports, wait, self.seats.touch, bind=bind)
        self.relay.start()
        threading.Thread(target=self._tls_loop, name="moon-tls", daemon=True).start()
        threading.Thread(target=self._game_http_loop, name="moon-http", daemon=True).start()
        log(
            f"tls :{self.ports['https']}, http :{self.ports['http']}, "
            f"rtsp :{self.ports['rtsp']}, udp {self.ports['udp']} (gs-relay)"
        )

    def serve(self):
        self.start()
        self._stop.wait()

    def _remember(self, client_ip, pod_ip, gsuser, touch=True):
        with self._map_lock:
            self.by_ip[client_ip] = {"pod": pod_ip, "user": gsuser, "when": time.time()}
        relay = getattr(self, "relay", None)
        if relay is not None:
            relay.map(client_ip, pod_ip, gsuser)
        if touch:
            self.seats.touch(gsuser)

    def _lookup_ip(self, client_ip):
        with self._map_lock:
            return self.by_ip.get(client_ip)

    def _bind(self, kind, port):
        sock = socket.socket(socket.AF_INET, kind)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
        except OSError as exc:
            log(f"fatal: bind {port}: {exc}")
            os._exit(1)
        return sock

    def _state_root(self):
        return getattr(self.cfg, "persist_mount", "") or getattr(self.cfg, "persist_root", "")

    def _state_kwargs(self):
        return {
            "config_rel": getattr(self.cfg, "sunshine_config_rel", ".config/sunshine"),
            "state_name": getattr(self.cfg, "sunshine_state_file", "sunshine_state.json"),
        }

    def _reset_remote(self, user, placed):
        host = getattr(placed, "proxy_host", "") or ""
        node = getattr(placed, "node", "") or ""
        name = user.name if user is not None else "?"
        log(
            f"{name}: seat is on {node or 'another node'}"
            f" ({host or 'no advertised address'}); resetting so the client tries the next address"
        )

    def _steer(self, sock, user, placed, target, https):
        """Wrong node. True means this socket is done. False means splice."""
        mode = (getattr(self.cfg, "http_foreign", "redirect") or "redirect").lower()
        host = getattr(placed, "proxy_host", "") or ""
        info = getattr(placed, "info", "") or ""
        path = urllib.parse.urlsplit(target).path
        name = user.name if user is not None else ""
        with self._map_lock:
            already = (name, host) in self._pointed
        action = moonlight_foreign(mode, host, info, path, already)
        if action == "splice":
            return False
        if action == "point":
            with self._map_lock:
                self._pointed.add((name, host))
            _cert, _key, uid = self.store.server_material()
            try:
                sock.sendall(serverinfo_xml(
                    True, uid, host, https=https,
                    http_port=self.ports["http"], https_port=self.ports["https"],
                    external_ip=host,
                ))
            except OSError as exc:
                log(f"{name or '?'}: point {exc}")
                reset_tcp(sock)
                return True
            log(f"{name or '?'}: seat is on {getattr(placed, 'node', '') or 'another node'}; "
                f"told Moonlight to retry {host}")
            return True
        self._reset_remote(user, placed)
        reset_tcp(sock)
        return True

    def _tls_loop(self):
        cert, key, _uid = self.store.server_material()
        cert_path, key_path = _write_temp(cert), _write_temp(key)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert_path, key_path)
        ctx.verify_mode = ssl.CERT_OPTIONAL
        with self._trust_lock:
            self._tls_ctx = ctx
        self._refresh_trust()
        listen = self._bind(socket.SOCK_STREAM, self.ports["https"])
        listen.listen(64)
        while not self._stop.is_set():
            try:
                conn, addr = listen.accept()
            except OSError:
                continue
            threading.Thread(target=self._tls_client, args=(ctx, conn, addr), daemon=True).start()

    def _tls_client(self, ctx, conn, addr):
        backend = None
        ssock = None
        try:
            self._refresh_trust()
            conn.settimeout(self.cfg.ready_timeout + 30)
            ssock = ctx.wrap_socket(conn, server_side=True)
            try:
                peer = ssock.getpeercert(binary_form=True)
            except ssl.SSLError:
                peer = None
            buf = b""
            while True:
                raw, buf = read_http(ssock, buf)
                if raw is None:
                    break
                line = raw.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
                parts = line.split(" ")
                target = parts[1] if len(parts) > 1 else "/"
                parsed = urllib.parse.urlsplit(target)
                query = urllib.parse.parse_qs(parsed.query)
                if parsed.path == "/pair":
                    if query.get("phrase", [""])[0] == "pairchallenge":
                        known = self.store.client_for_der(peer) is not None
                        ssock.sendall(xml_response({"paired": 1 if known else 0}))
                    else:
                        cert, key, _uid = self.store.server_material()
                        reply = self.pairs.handle(query, cert, key)
                        self._refresh_trust()
                        ssock.sendall(reply)
                    continue
                client = self.store.client_for_der(peer)
                user = self.directory.get(client["gsuser"]) if client else None
                if parsed.path == "/serverinfo":
                    placed = self.seats.lookup(user) if user else None
                    kind = getattr(placed, "kind", "") if placed else ""
                    if kind == "remote":
                        if self._steer(ssock, user, placed, target, https=True):
                            return
                        target_ip = placed.info
                    elif kind != "local":
                        _c, _k, uid = self.store.server_material()
                        ssock.sendall(serverinfo_xml(
                            user is not None, uid, _sock_ip(ssock), https=True,
                            http_port=self.ports["http"], https_port=self.ports["https"],
                        ))
                        continue
                    else:
                        target_ip = placed.info
                    # Moonlight polls this while the app is open. It does not
                    # create a seat, but a seat that is already up stays up.
                    count = True
                else:
                    if user is None:
                        ssock.sendall(fail_xml("not paired" if client is None else f"no seat for {client['gsuser']}"))
                        continue
                    placed = self.seats.ensure(user)
                    kind = getattr(placed, "kind", "")
                    info = getattr(placed, "info", "")
                    if kind == "remote":
                        if self._steer(ssock, user, placed, target, https=True):
                            return
                        info = placed.info
                    elif kind != "local":
                        ssock.sendall(fail_xml(f"seat {kind} {info}"))
                        continue
                    target_ip, count = info, True
                if backend is None:
                    backend = self._backend(target_ip, user.name)
                    if backend is None:
                        ssock.sendall(fail_xml("pod tls failed; the shared proxy cert is installed at seat boot"))
                        continue
                    self._remember(addr[0], target_ip, user.name, touch=count)
                elif count:
                    self.seats.touch(user.name)
                backend.sendall(raw)
                resp, _rest = read_response(backend)
                if resp is None:
                    break
                _cert, _key, uid = self.store.server_material()
                ssock.sendall(rewrite_backend_response(resp, facing_host(raw, ssock), uid))
        except (OSError, ssl.SSLError) as exc:
            log(f"tls {addr[0]}: {exc}")
        finally:
            for sock in (backend, ssock, conn):
                if sock is None:
                    continue
                try:
                    sock.close()
                except OSError:
                    pass

    def _backend(self, pod_ip, gsuser):
        cert, key, _uid = self.store.server_material()
        if not cert or not key:
            log(f"{gsuser}: proxy certificate missing from the store")
            return None
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.load_cert_chain(_write_temp(cert), _write_temp(key))
        try:
            raw = socket.create_connection((pod_ip, self.ports["https"]), timeout=20)
            raw.settimeout(None)
            return ctx.wrap_socket(raw, server_hostname="sunshine")
        except (OSError, ssl.SSLError) as exc:
            log(f"{gsuser}: backend tls {exc}")
            return None

    def _game_http_loop(self):
        listen = self._bind(socket.SOCK_STREAM, self.ports["http"])
        listen.listen(64)
        while not self._stop.is_set():
            try:
                conn, addr = listen.accept()
            except OSError:
                continue
            threading.Thread(target=self._game_http, args=(conn, addr), daemon=True).start()

    def _game_http(self, conn, addr):
        """Pairing phases are plain HTTP. serverinfo here is always unpaired."""
        try:
            conn.settimeout(PIN_WAIT + 30)
            buf = b""
            while True:
                raw, buf = read_http(conn, buf)
                if raw is None:
                    break
                line = raw.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
                parts = line.split(" ")
                target = parts[1] if len(parts) > 1 else "/"
                parsed = urllib.parse.urlsplit(target)
                query = urllib.parse.parse_qs(parsed.query)
                if parsed.path == "/pair":
                    cert, key, _uid = self.store.server_material()
                    reply = self.pairs.handle(query, cert, key)
                    self._refresh_trust()
                    conn.sendall(reply)
                    continue
                if parsed.path == "/unpair":
                    uid = query.get("uniqueid", [""])[0]
                    if uid:
                        self._drop_uid(uid)
                    conn.sendall(xml_response({"paired": 1}))
                    continue
                if parsed.path == "/serverinfo":
                    _c, _k, uid = self.store.server_material()
                    conn.sendall(serverinfo_xml(
                        False, uid, _sock_ip(conn), https=False,
                        http_port=self.ports["http"], https_port=self.ports["https"],
                    ))
                    continue
                mapped = self._lookup_ip(addr[0])
                if not mapped:
                    conn.sendall(fail_xml("not paired"))
                    continue
                back = socket.create_connection((mapped["pod"], self.ports["http"]), timeout=10)
                try:
                    back.sendall(raw)
                    resp, _rest = read_response(back)
                    if resp:
                        conn.sendall(resp)
                        self.seats.touch(mapped["user"])
                finally:
                    back.close()
        except OSError as exc:
            log(f"http {addr[0]}: {exc}")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _drop_uid(self, uid):
        def save(data):
            data["clients"] = [c for c in data["clients"] if c.get("uuid") != uid]
        self.store.update(save)

    def handle_admin(self, handler):
        path = urllib.parse.urlsplit(handler.path).path
        if not self._admin_ok(handler, path):
            return
        if path == "/admin/pin" and handler.command == "POST":
            self._post_pin(handler)
            return
        if path == "/admin/unpair" and handler.command == "POST":
            self._post_unpair(handler)
            return
        handler._page(200, self._page(), "text/html; charset=utf-8")

    def _admin_token(self):
        return hmac.new(self.cfg.secret, b"gs-admin\0" + self.cfg.admin_password.encode(), sha256).hexdigest()

    def _admin_ok(self, handler, path):
        password = self.cfg.admin_password
        if not password:
            return True
        token = ""
        for part in (handler.headers.get("Cookie") or "").split(";"):
            part = part.strip()
            if part.startswith("gs_admin="):
                token = urllib.parse.unquote(part.split("=", 1)[1])
        if _same(token, self._admin_token()):
            return True
        if path == "/admin/login" and handler.command == "POST":
            form = _form(handler)
            if _same(form.get("password", [""])[0], password):
                handler.send_response(302)
                handler.send_header(
                    "Set-Cookie",
                    "gs_admin=" + urllib.parse.quote(self._admin_token()) + "; HttpOnly; Path=/admin",
                )
                handler.send_header("Location", "/admin")
                handler.send_header("Content-Length", "0")
                handler.end_headers()
                return False
        handler._page(401, "<form method=post action=/admin/login><input type=password name=password><button>Admin</button></form>")
        return False

    def _page(self):
        data = self.store.snapshot()
        rows = []
        for client in data["clients"]:
            rows.append(
                f"<tr><td>{_e(client.get('name'))}</td><td>{_e(client.get('gsuser'))}</td>"
                f"<td><code>{client.get('fingerprint','')[:16]}</code></td>"
                f"<td><form method=post action=/admin/unpair><input type=hidden name=fingerprint value='{client.get('fingerprint','')}'>"
                f"<button>Remove</button></form></td></tr>"
            )
        pending = []
        for rec in data["pending"].values():
            if rec.get("phase") == "wait-pin" or not rec.get("pin"):
                opts = "".join(
                    f"<option value='{_e(name)}'>{_e(name)}</option>" for name in sorted(self.directory.users)
                )
                pending.append(
                    f"<li>{_e(rec.get('name'))} "
                    f"<form method=post action=/admin/pin>PIN <input name=pin size=4 required> "
                    f"<input type=hidden name=uniqueid value='{_e(rec.get('uniqueid'))}'>"
                    f"<select name=gsuser>{opts}</select> <button>Pair</button></form></li>"
                )
        cert = data.get("server_cert") or ""
        pods = []
        root = self._state_root()
        kwargs = self._state_kwargs()
        for name in sorted(self.directory.users):
            state = state_has_cert(root, name, cert, **kwargs) if cert else None
            state_s = {True: "proxy cert installed", False: "not in sunshine_state.json", None: "no state file"}.get(state, "")
            pods.append(f"<li><b>{_e(name)}</b> {_e(state_s)}</li>")
        fp = ""
        try:
            fp = fingerprint(cert)[:16] if cert else ""
        except Exception:
            fp = ""
        return f"""<!doctype html>
<meta charset="utf-8"><title>gs admin</title>
<style>body{{font:15px sans-serif;background:#111;color:#eee}} code{{color:#9cf}} button{{cursor:pointer}}</style>
<h1>Moonlight proxy</h1>
<p>Clients pair here. Seats trust one shared proxy certificate, generated on first start and installed at seat boot. Pods stay on the configured Sunshine ports.</p>
<p>Shared proxy cert <code>{_e(fp)}</code></p>
<h2>Waiting for a PIN</h2>
<ul>{''.join(pending) or '<li>none</li>'}</ul>
<h2>Paired clients</h2>
<table>{''.join(rows) or '<tr><td>none</td></tr>'}</table>
<h2>Seat trust</h2>
<ul>{''.join(pods) or '<li>add users to users.csv</li>'}</ul>
"""

    def _post_pin(self, handler):
        form = _form(handler)
        uid = form.get("uniqueid", [""])[0]
        pin = form.get("pin", [""])[0].strip()
        gsuser = form.get("gsuser", [""])[0]
        if gsuser not in self.directory.users or not pin.isdigit() or len(pin) != 4:
            handler._page(400, "pin must be 4 digits and gsuser must exist\n", "text/plain")
            return

        def save(data):
            rec = data["pending"].get(uid)
            if rec:
                rec["pin"] = pin
                rec["gsuser"] = gsuser
        self.store.update(save)
        handler.send_response(302)
        handler.send_header("Location", "/admin")
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    def _post_unpair(self, handler):
        fp = _form(handler).get("fingerprint", [""])[0]

        def save(data):
            data["clients"] = [c for c in data["clients"] if c.get("fingerprint") != fp]
        self.store.update(save)
        handler.send_response(302)
        handler.send_header("Location", "/admin")
        handler.send_header("Content-Length", "0")
        handler.end_headers()


def push_sunshine_pin(pod_ip, pin, user, password, web_port=SUNSHINE_HTTP + WEB_OFFSET):
    body = json.dumps({"pin": pin, "name": "gs-proxy"}).encode()
    ctx = ssl._create_unverified_context()
    req = __import__("urllib.request", fromlist=["Request"]).Request(
        f"https://{pod_ip}:{web_port}/api/pin", data=body, method="POST"
    )
    req.add_header("Content-Type", "application/json")
    if user:
        token = __import__("base64").b64encode(f"{user}:{password}".encode()).decode()
        req.add_header("Authorization", "Basic " + token)
    try:
        with __import__("urllib.request", fromlist=["urlopen"]).urlopen(req, context=ctx, timeout=10) as resp:
            text = resp.read().decode("utf-8", "replace")[:300]
            lowered = text.lower()
            if "false" in lowered and "true" not in lowered:
                return False, text or "rejected"
            return True, text or "ok"
    except Exception as exc:
        return False, str(exc)


def _form(handler):
    length = int(handler.headers.get("Content-Length", "0") or "0")
    raw = handler.rfile.read(min(length, 1 << 20)) if length else b""
    return urllib.parse.parse_qs(raw.decode("utf-8", "replace"))


def _same(a, b):
    a = a or ""
    b = b or ""
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a, b)


def _e(value):
    text = value or ""
    amp = chr(38)
    return (
        text.replace(amp, amp + "amp;")
        .replace("<", amp + "lt;")
        .replace(">", amp + "gt;")
        .replace("'", amp + "#39;")
        .replace(chr(34), amp + "quot;")
    )

