"""What a proxy is allowed to ask the orchestrator."""
import hmac
import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gs.model import api_token, log, place_dict

class OrchestratorApi:
    def __init__(self, cfg, directory, seats):
        self.cfg = cfg
        self.directory = directory
        self.seats = seats

    def serve(self):
        publish_proxy_cert(self.cfg)
        threading.Thread(target=self._reap, name="reap", daemon=True).start()
        threading.Thread(target=self._reload, name="reload", daemon=True).start()
        if self.seats.board is not None:
            threading.Thread(target=self._board, name="board", daemon=True).start()
        log(f"orchestrator api on :{self.cfg.http_port}, idle {self.cfg.idle_seconds}s")
        self._http()

    def _reap(self):
        while True:
            time.sleep(15)
            try:
                self.seats.reap()
            except Exception as exc:
                log(f"reap: {exc}")

    def _board(self):
        while True:
            try:
                self.seats.reconcile()
            except Exception as exc:
                log(f"inventory: {exc}")
            time.sleep(5)

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
                placed = api.seats.ensure(user, prefer_node=prefer)
                if placed.kind == "inventory":
                    self._json(503, place_dict(placed))
                    return
                self._json(200, place_dict(placed))

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



def publish_proxy_cert(cfg):
    import moonlight_proxy
    moonlight_proxy.Store(cfg.proxy_store, cert_path=cfg.proxy_cert_publish or None)
