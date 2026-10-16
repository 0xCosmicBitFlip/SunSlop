"""Selkies login and the reverse proxy to the seat on this node."""
import selectors
import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gs.model import (
    HOP, PORT_HI, PORT_LO, Place, SamlAuthenticator, issue_token, log, pod_port,
    public_base, read_token,
)
from gs.net import _read_http_head, reset, splice

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

