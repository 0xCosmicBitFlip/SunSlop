"""python3 orchestrator/moonlight_proxy.py. Not imported at runtime."""
import hmac
import json
import os
import socket
import ssl
import tempfile
import threading
import time
import urllib.parse
from hashlib import sha256

import gs.moonlight as moonlight
import gs.pairing as pairing
import gs.protocol as protocol
import gs.relay as relay
import gs.store as store


def _bind():
    g = globals()
    for mod in (protocol, store, pairing, relay, moonlight):
        for name, value in vars(mod).items():
            if not name.startswith("__"):
                g.setdefault(name, value)


_bind()

def self_test():
    import tempfile
    key = aes_key(b"\x00" * 16, "1234")
    assert key == sha256(b"\x00" * 16 + b"1234").digest()[:16]
    blob = aes_ecb(key, b"0123456789abcdef")
    assert aes_ecb(key, blob, decrypt=True) == b"0123456789abcdef"
    store = Store(os.path.join(tempfile.mkdtemp(), "store.json"))
    assert os.path.isfile(store.cert_path)
    assert "BEGIN CERTIFICATE" in open(store.cert_path).read()
    # A seat bind-mounts this inode. Rewriting the directory entry would not
    # update that mount; the bytes have to change in place.
    held = os.open(store.cert_path, os.O_RDONLY)
    try:
        store._publish("-----BEGIN CERTIFICATE-----\nNEW\n-----END CERTIFICATE-----\n")
        os.lseek(held, 0, os.SEEK_SET)
        seen = os.read(held, 4096)
    finally:
        os.close(held)
    assert b"NEW" in seen, seen
    server = PairServer(store)
    cert, key_pem = store.server_material()[0], store.server_material()[1]
    again = Store(store.path, cert_path=store.cert_path)
    assert again.server_material()[0] == cert
    pin = "4242"
    salt = secrets.token_bytes(16)
    client_cert, client_key = make_cert("moonlight-test")
    uid = "abc"

    def answer():
        time.sleep(0.2)
        store.update(lambda data: data["pending"].__setitem__(uid, {**data["pending"].get(uid, {}), "pin": pin, "gsuser": "gsuser1"}) or data)

    holder = {}

    def phase1():
        query = {
            "phrase": ["getservercert"],
            "uniqueid": [uid],
            "salt": [hx(salt)],
            "clientcert": [hx(client_cert.encode())],
            "devicename": ["test"],
        }
        holder["resp"] = server.handle(query, cert, key_pem)

    threading.Thread(target=answer, daemon=True).start()
    phase1()
    xml = parse_xml(holder["resp"].split(b"\r\n\r\n", 1)[1].decode())
    assert xml["paired"] == "1"
    assert unhex(xml["plaincert"]) == cert.encode()
    challenge = secrets.token_bytes(16)
    enc = aes_ecb(aes_key(salt, pin), challenge)
    resp = server.handle({"uniqueid": [uid], "clientchallenge": [hx(enc)]}, cert, key_pem)
    xml = parse_xml(resp.split(b"\r\n\r\n", 1)[1].decode())
    plain = aes_ecb(aes_key(salt, pin), unhex(xml["challengeresponse"]), decrypt=True)
    server_hash, server_challenge = plain[:32], plain[32:48]
    client_secret = secrets.token_bytes(16)
    client_hash = sha256(server_challenge + cert_signature(client_cert) + client_secret).digest()
    resp = server.handle({"uniqueid": [uid], "serverchallengeresp": [hx(aes_ecb(aes_key(salt, pin), client_hash))]}, cert, key_pem)
    xml = parse_xml(resp.split(b"\r\n\r\n", 1)[1].decode())
    blob = unhex(xml["pairingsecret"])
    assert verify256(cert, blob[:16], blob[16:])
    expect = sha256(challenge + cert_signature(cert) + blob[:16]).digest()
    assert expect == server_hash
    secret_sig = sign256(client_key, client_secret)
    resp = server.handle({"uniqueid": [uid], "clientpairingsecret": [hx(client_secret + secret_sig)]}, cert, key_pem)
    xml = parse_xml(resp.split(b"\r\n\r\n", 1)[1].decode())
    assert xml["paired"] == "1"
    saved = store.client_for_der(x509.load_pem_x509_certificate(client_cert.encode()).public_bytes(serialization.Encoding.DER))
    assert saved["gsuser"] == "gsuser1"
    home = tempfile.mkdtemp()
    user_dir = os.path.join(home, "gsuser0", ".config", "sunshine")
    os.makedirs(user_dir)
    json.dump(
        {"root": {"named_devices": [{"name": "gs-proxy", "cert": cert, "uuid": "u"}]}},
        open(os.path.join(user_dir, "sunshine_state.json"), "w"),
    )
    assert state_has_cert(home, "gsuser0", cert) is True
    assert state_has_cert(home, "gsuser0", make_cert("other")[0]) is False
    info = serverinfo_xml(True, "abc", "10.1.1.2", external_ip="10.1.1.2")
    assert b"ExternalIP" in info and b"10.1.1.2" in info
    pointed = serverinfo_xml(True, "abc", "10.0.0.2", https=True, external_ip="10.0.0.2")
    assert b"<LocalIP>10.0.0.2</LocalIP>" in pointed
    assert b"<ExternalIP>10.0.0.2</ExternalIP>" in pointed
    assert b"status_code=\"200\"" in pointed
    assert moonlight_foreign("redirect", "10.0.0.2", "", "/serverinfo", False) == "point"
    assert moonlight_foreign("redirect", "10.0.0.2", "", "/serverinfo", True) == "reset"
    assert moonlight_foreign("redirect", "10.0.0.2", "", "/launch", False) == "reset"
    assert moonlight_foreign("redirect", "", "", "/serverinfo", False) == "reset"
    assert moonlight_foreign("reset", "10.0.0.2", "", "/serverinfo", False) == "reset"
    assert moonlight_foreign("proxy", "10.0.0.2", "10.9.0.4", "/serverinfo", False) == "splice"
    assert moonlight_foreign("proxy", "10.0.0.2", "", "/serverinfo", False) == "point"
    sample = http_response(
        b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        b"<root status_code=\"200\"><uniqueid>SEAT</uniqueid>"
        b"<mac>00:11:22:33:44:55</mac>"
        b"<LocalIP>10.9.9.9</LocalIP><ExternalIP>10.9.9.9</ExternalIP>"
        b"<currentgame>7</currentgame>"
        b"<sessionUrl0>rtsp://10.9.9.9:48010</sessionUrl0>"
        b"<sessionUrl1>rtspenc://10.9.9.9:48010</sessionUrl1></root>",
        b"application/xml",
    )
    rewritten = rewrite_backend_response(sample, "5.5.5.5:47984", "proxyuid")
    assert b"<LocalIP>5.5.5.5</LocalIP>" in rewritten
    assert b"<ExternalIP>5.5.5.5</ExternalIP>" in rewritten
    assert b"<uniqueid>proxyuid</uniqueid>" in rewritten
    assert f"<mac>{server_mac('proxyuid')}</mac>".encode() in rewritten
    assert b"rtsp://5.5.5.5:48010" in rewritten
    assert b"rtspenc://5.5.5.5:48010" in rewritten
    assert b"<currentgame>7</currentgame>" in rewritten
    assert b"10.9.9.9" not in rewritten
    assert b"Content-Length: " + str(rewritten.split(b"\r\n\r\n", 1)[1].__len__()).encode() in rewritten
    assert safe_host("5.5.5.5:47984") == "5.5.5.5"
    assert safe_host("[2001:db8::1]:47984") == "[2001:db8::1]"
    assert safe_host("bad host") == ""
    _relay_test()
    _loopback()
    _flow_test()
    print("moonlight self-test ok")


def _relay_test():
    """UDP return path and the RTSP splice, through the same control socket.

    The relay listens on 127.0.0.4, not 127.0.0.1. A local HTTP probe talks
    to localhost and would otherwise be spliced as if it were the client.
    """
    udp_port, rtsp_port = _free_pair()
    touches = []
    relay = RustRelay(
        {"udp": (udp_port,), "rtsp": rtsp_port},
        rtsp_wait=1,
        touch=lambda name: touches.append(name),
        bind="127.0.0.4",
    )
    relay.start()
    client = other = stranger = pod = closed = None
    try:
        pod = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        pod.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        pod.bind(("127.0.0.2", udp_port))
        echo_ready = threading.Event()
        echo_box = {}

        def echo():
            listen = socket.socket()
            listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen.bind(("127.0.0.2", rtsp_port))
            listen.listen(4)
            echo_ready.set()
            try:
                conn, _addr = listen.accept()
                conn.settimeout(3)
                try:
                    data = b""
                    while len(data) < 7:
                        chunk = conn.recv(32)
                        if not chunk:
                            break
                        data += chunk
                    echo_box["got"] = data
                    conn.sendall(b"RTSP/1.0 200")
                finally:
                    conn.close()
            finally:
                listen.close()

        threading.Thread(target=echo, daemon=True).start()
        assert echo_ready.wait(2)

        client_box = {}

        def rtsp_client():
            sock = socket.socket()
            try:
                sock.bind(("127.0.0.3", 0))
                sock.settimeout(3)
                sock.connect(("127.0.0.4", rtsp_port))
                sock.sendall(b"OPTIONS")
                client_box["reply"] = sock.recv(32)
            except OSError as exc:
                client_box["err"] = exc
            finally:
                sock.close()

        threading.Thread(target=rtsp_client, daemon=True).start()
        time.sleep(0.3)
        relay.map("127.0.0.3", "127.0.0.2", "gsuser9")
        deadline = time.time() + 3
        while time.time() < deadline and "reply" not in client_box and "err" not in client_box:
            time.sleep(0.05)
        assert client_box.get("reply") == b"RTSP/1.0 200", client_box
        assert echo_box.get("got") == b"OPTIONS", echo_box

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("127.0.0.3", 0))
        client.sendto(b"ping", ("127.0.0.4", udp_port))
        pod.settimeout(2)
        data, addr = pod.recvfrom(64)
        assert data == b"ping", data
        assert addr[0] == "127.0.0.4" and addr[1] == udp_port, addr
        pod.sendto(b"pong", addr)
        client.settimeout(2)
        reply, _who = client.recvfrom(64)
        assert reply == b"pong"

        other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        other.bind(("127.0.0.5", 0))
        relay.map("127.0.0.5", "127.0.0.2", "gsuser1")
        other.sendto(b"ping2", ("127.0.0.4", udp_port))
        data, addr = pod.recvfrom(64)
        assert data == b"ping2"
        pod.sendto(b"pong2", addr)
        other.settimeout(2)
        reply, _who = other.recvfrom(64)
        assert reply == b"pong2"
        client.settimeout(0.4)
        try:
            stale = client.recvfrom(64)
        except socket.timeout:
            stale = None
        assert stale is None, stale

        stranger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        stranger.bind(("127.0.0.6", 0))
        stranger.sendto(b"nope", ("127.0.0.4", udp_port))
        pod.settimeout(0.4)
        try:
            leaked = pod.recvfrom(64)
        except socket.timeout:
            leaked = None
        assert leaked is None, leaked

        closed = socket.socket()
        closed.bind(("127.0.0.6", 0))
        closed.settimeout(3)
        closed.connect(("127.0.0.4", rtsp_port))
        closed.sendall(b"NOPE")
        try:
            got = closed.recv(16)
        except ConnectionResetError:
            # Dropping an unread TCP socket is a RST. Either way the client
            # is not spliced to a pod.
            got = b""
        assert got == b""
        assert "gsuser9" in touches
        assert "gsuser1" in touches
    finally:
        relay.stop()
        for obj in (pod, client, other, stranger, closed):
            if obj is None:
                continue
            try:
                obj.close()
            except OSError:
                pass


def _free_pair():
    """One UDP port and one TCP port free on the loopback addresses the test uses."""
    ips = ("127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.6")
    for udp_port in range(26000, 42000, 3):
        rtsp_port = udp_port + 1
        held = []
        try:
            for ip in ips:
                for port, kind in ((udp_port, socket.SOCK_DGRAM), (rtsp_port, socket.SOCK_STREAM)):
                    sock = socket.socket(socket.AF_INET, kind)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind((ip, port))
                    held.append(sock)
        except OSError:
            for sock in held:
                sock.close()
            continue
        for sock in held:
            sock.close()
        return udp_port, rtsp_port
    raise SystemExit("no free relay ports")


def _loopback():
    import tempfile
    store = Store(os.path.join(tempfile.mkdtemp(), "loop.json"))
    http_box, https_box = [], []
    http_ready, https_ready = threading.Event(), threading.Event()

    def serve_http():
        pairs = PairServer(store)
        listen = socket.socket()
        listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen.bind(("127.0.0.1", 0))
        listen.listen(4)
        http_box.append(listen.getsockname()[1])
        http_ready.set()
        deadline = time.time() + 60
        listen.settimeout(1)
        conn = None
        try:
            while time.time() < deadline:
                try:
                    conn, _addr = listen.accept()
                    break
                except socket.timeout:
                    continue
        except Exception:
            listen.close()
            return
        if conn is None:
            listen.close()
            return
        conn.settimeout(30)
        buf = b""
        try:
            while True:
                raw, buf = read_http(conn, buf)
                if raw is None:
                    break
                line = raw.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
                target = line.split(" ")[1]
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(target).query)
                cert, key, _uid = store.server_material()
                conn.sendall(pairs.handle(query, cert, key))
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
            listen.close()

    def serve_https():
        cert, key, _uid = store.server_material()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(_write_temp(cert), _write_temp(key))
        listen = socket.socket()
        listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen.bind(("127.0.0.1", 0))
        listen.listen(4)
        https_box.append(listen.getsockname()[1])
        https_ready.set()
        deadline = time.time() + 60
        listen.settimeout(1)
        try:
            while time.time() < deadline:
                try:
                    conn, _addr = listen.accept()
                except socket.timeout:
                    continue
                try:
                    ssock = ctx.wrap_socket(conn, server_side=True)
                except ssl.SSLError:
                    conn.close()
                    continue
                try:
                    ssock.settimeout(10)
                    raw, _buf = read_http(ssock, b"")
                    if raw is None:
                        ssock.close()
                        continue
                    line = raw.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
                    target = line.split(" ")[1]
                    query = urllib.parse.parse_qs(urllib.parse.urlsplit(target).query)
                    c, k, _uid = store.server_material()
                    ssock.sendall(PairServer(store).handle(query, c, k))
                    ssock.close()
                    if query.get("phrase", [""])[0] == "pairchallenge":
                        break
                except OSError:
                    try:
                        conn.close()
                    except OSError:
                        pass
        finally:
            listen.close()

    def feed():
        deadline = time.time() + 10
        while time.time() < deadline:
            if store.snapshot()["pending"]:
                def save(data):
                    for rec in data["pending"].values():
                        if not rec.get("pin"):
                            rec["pin"] = "9999"
                            rec["gsuser"] = "gsuser9"
                store.update(save)
                return
            time.sleep(0.05)

    threading.Thread(target=serve_http, daemon=True).start()
    threading.Thread(target=serve_https, daemon=True).start()
    assert http_ready.wait(5) and https_ready.wait(5)
    cert, key = make_cert("proxy-loop")
    threading.Thread(target=feed, daemon=True).start()
    ok, detail = client_pair("127.0.0.1", "9999", cert, key, http_box[0], https_box[0])
    assert ok, detail
    saved = store.client_for_der(
        x509.load_pem_x509_certificate(cert.encode()).public_bytes(serialization.Encoding.DER)
    )
    assert saved and saved["gsuser"] == "gsuser9"


def _free_base():
    offsets = {
        -5: (socket.SOCK_STREAM,),
        0: (socket.SOCK_STREAM,),
        9: (socket.SOCK_DGRAM,),
        10: (socket.SOCK_DGRAM,),
        11: (socket.SOCK_DGRAM,),
        13: (socket.SOCK_DGRAM,),
        21: (socket.SOCK_STREAM, socket.SOCK_DGRAM),
    }
    for base in range(25000, 42000, 37):
        held = []
        try:
            for off, kinds in offsets.items():
                for kind in kinds:
                    sock = socket.socket(socket.AF_INET, kind)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind(("0.0.0.0", base + off))
                    held.append(sock)
        except OSError:
            for sock in held:
                sock.close()
            continue
        for sock in held:
            sock.close()
        return base
    raise SystemExit("no free sunshine port block")


def _wait_port(port):
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=0.2)
            sock.close()
            return
        except OSError:
            time.sleep(0.05)
    raise SystemExit(f"port {port} did not open")


def _read_one(sock):
    sock.settimeout(5)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return buf
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
    while len(rest) < length:
        chunk = sock.recv(4096)
        if not chunk:
            break
        rest += chunk
    return head + b"\r\n\r\n" + rest[:length]


def _flow_test():
    """Moonlight pair, then a seat that answers with its own pod address.

    The client cert is self-signed, which is what Moonlight sends. The seat
    trusts the proxy cert seat-boot installed. The client must see its own
    host in LocalIP and the RTSP url, then a RST when the seat moves.
    """
    import importlib.util
    import tempfile
    from types import SimpleNamespace

    seat_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "image", "seat-boot.py")
    spec = importlib.util.spec_from_file_location("seat_boot_flow", seat_path)
    seat_boot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seat_boot)

    base = _free_base()
    home = tempfile.mkdtemp()
    cfg = SimpleNamespace(
        proxy_store=os.path.join(home, "store.json"),
        proxy_cert_publish=os.path.join(home, "proxy-client.crt"),
        sunshine_base=base,
        https_offset=-5,
        web_offset=1,
        rtsp_offset=21,
        udp_offsets=(9, 10, 11, 13, 21),
        ready_timeout=3,
        http_foreign="redirect",
        persist_mount=home,
        sunshine_config_rel=".config/sunshine",
        sunshine_state_file="sunshine_state.json",
        secret=b"0123456789abcdef",
        admin_password="",
        relay_bind="127.0.0.4",
    )

    class User:
        def __init__(self, name):
            self.name = name

    class Directory:
        def __init__(self):
            self.users = {"gsuser9": User("gsuser9")}

        def get(self, name):
            return self.users.get(name)

    class Place:
        def __init__(self):
            self.kind = "local"
            self.info = "127.0.0.1"
            self.proxy_host = "4.4.4.4"
            self.node = "node-a"

    class Seats:
        def __init__(self):
            self.place = Place()
            self.touches = []
            self.ensured = []

        def lookup(self, user):
            if user is None or self.place is None:
                return None
            return self.place

        def ensure(self, user):
            self.ensured.append(user.name)
            return self.place

        def touch(self, name):
            self.touches.append(name)

    seats = Seats()
    proxy = MoonlightProxy(cfg, Directory(), seats)
    updates, paired = seat_boot.apply_boot(
        os.path.join(home, "sunshine.conf"),
        os.path.join(home, "gsuser9", ".config", "sunshine", "sunshine_state.json"),
        {
            "SUNSHINE_BASE_PORT": str(base),
            "GS_PROXY_CERT": cfg.proxy_cert_publish,
            "GS_PROXY_CERT_REQUIRED": "1",
            "GS_PROXY_CERT_WAIT": "1",
            "GS_PROXY_CLIENT_NAME": "gs-proxy",
        },
    )
    assert paired, "seat-boot did not install the proxy cert"
    assert updates["file_state"].endswith("sunshine_state.json")
    installed = json.load(open(os.path.join(
        home, "gsuser9", ".config", "sunshine", "sunshine_state.json"
    )))
    installed_pem = installed["root"]["named_devices"][0]["cert"]
    assert installed["root"]["named_devices"][0]["enabled"] is True
    assert fingerprint(installed_pem) == fingerprint(proxy.store.server_material()[0])

    fake_port = _fake_sunshine(installed_pem)
    real_backend = MoonlightProxy._backend

    def backend(pod_ip, gsuser, _port=fake_port):
        saved = proxy.ports["https"]
        proxy.ports["https"] = _port
        try:
            return real_backend(proxy, pod_ip, gsuser)
        finally:
            proxy.ports["https"] = saved

    proxy._backend = backend
    proxy.start()
    try:
        _wait_port(proxy.ports["http"])
        _flow_body(proxy, seats)
    finally:
        relay = getattr(proxy, "relay", None)
        if relay is not None:
            relay.stop()


def _flow_body(proxy, seats):

    def feed():
        deadline = time.time() + 10
        while time.time() < deadline:
            if proxy.store.snapshot()["pending"]:
                def save(data):
                    for rec in data["pending"].values():
                        if not rec.get("pin"):
                            rec["pin"] = "2468"
                            rec["gsuser"] = "gsuser9"
                proxy.store.update(save)
                return
            time.sleep(0.05)

    threading.Thread(target=feed, daemon=True).start()
    cert, key = make_cert("moonlight-phone")
    ok, detail = client_pair("127.0.0.1", "2468", cert, key, proxy.ports["http"], proxy.ports["https"])
    assert ok, detail
    other_cert, other_key = make_cert("someone-else")
    try:
        _tls_exchange(proxy.ports["https"], other_cert, other_key, "/serverinfo", "5.5.5.5")
        raise SystemExit("unpaired client certificate was accepted")
    except (ssl.SSLError, OSError):
        pass

    info, err = _tls_exchange(proxy.ports["https"], cert, key, "/serverinfo", "5.5.5.5:47984")
    assert err is None, err
    assert b"<LocalIP>5.5.5.5</LocalIP>" in info
    assert b"10.9.9.9" not in info
    assert b"<currentgame>7</currentgame>" in info
    uid = proxy.store.server_material()[2]
    assert f"<uniqueid>{uid}</uniqueid>".encode() in info
    assert seats.touches == ["gsuser9"], seats.touches
    assert seats.ensured == []
    held = len(seats.touches)
    saved = seats.place
    seats.place = None
    down, err = _tls_exchange(proxy.ports["https"], cert, key, "/serverinfo", "5.5.5.5")
    assert err is None, err
    assert b"<PairStatus>1</PairStatus>" in down
    assert b"<currentgame>0</currentgame>" in down
    assert seats.ensured == []
    assert len(seats.touches) == held
    seats.place = saved
    launch, err = _tls_exchange(proxy.ports["https"], cert, key, "/launch?appid=1", "5.5.5.5")
    assert err is None, err
    assert b"rtsp://5.5.5.5:48010" in launch
    assert b"rtspenc://5.5.5.5:48010" in launch
    assert b"<currentgame>7</currentgame>" in launch
    assert b"10.9.9.9" not in launch

    seats.place.kind = "remote"
    seats.place.info = ""
    pointed, err = _tls_exchange(proxy.ports["https"], cert, key, "/serverinfo", "5.5.5.5")
    assert err is None, err
    assert b"<LocalIP>4.4.4.4</LocalIP>" in pointed
    assert b"<ExternalIP>4.4.4.4</ExternalIP>" in pointed
    try:
        again, _err = _tls_exchange(proxy.ports["https"], cert, key, "/serverinfo", "5.5.5.5")
    except OSError:
        again = b""
    assert b"<LocalIP>" not in again
    _reset_check(proxy.ports["https"], cert, key)


def _fake_sunshine(trust_pem):
    cert, key = make_cert("seat-sunshine")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(_write_temp(cert), _write_temp(key))
    ctx.verify_mode = ssl.CERT_OPTIONAL
    text = trust_pem if str(trust_pem).endswith("\n") else str(trust_pem) + "\n"
    ctx.load_verify_locations(cadata=text)
    listen = socket.socket()
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(("127.0.0.1", 0))
    listen.listen(8)
    port = listen.getsockname()[1]

    def serve():
        while True:
            try:
                conn, _addr = listen.accept()
            except OSError:
                return
            try:
                ssock = ctx.wrap_socket(conn, server_side=True)
                ssock.settimeout(5)
                raw, _rest = read_http(ssock, b"")
                if raw is None:
                    ssock.close()
                    continue
                line = raw.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
                path = line.split(" ")[1]
                if path.startswith("/launch"):
                    body = (
                        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                        "<root status_code=\"200\">"
                        "<sessionUrl0>rtsp://10.9.9.9:48010</sessionUrl0>"
                        "<sessionUrl1>rtspenc://10.9.9.9:48010</sessionUrl1>"
                        "<currentgame>7</currentgame></root>"
                    ).encode()
                else:
                    body = (
                        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                        "<root status_code=\"200\"><uniqueid>SEATUNIQUEID</uniqueid>"
                        "<LocalIP>10.9.9.9</LocalIP><PairStatus>1</PairStatus>"
                        "<currentgame>7</currentgame></root>"
                    ).encode()
                ssock.sendall(http_response(body, b"application/xml"))
                ssock.close()
            except OSError:
                try:
                    conn.close()
                except OSError:
                    pass

    threading.Thread(target=serve, daemon=True).start()
    return port


def _tls_exchange(port, cert, key, path, host):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(_write_temp(cert), _write_temp(key))
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    ssock = ctx.wrap_socket(raw, server_hostname="sunshine")
    ssock.sendall(
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    )
    try:
        return _read_one(ssock), None
    except ConnectionResetError:
        raise
    finally:
        try:
            ssock.close()
        except OSError:
            pass


def _reset_check(port, cert, key):
    """The foreign reset has to be a TCP RST, not a TLS close_notify."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(_write_temp(cert), _write_temp(key))
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    ssock = ctx.wrap_socket(raw, server_hostname="sunshine")
    ssock.sendall(b"GET /serverinfo HTTP/1.1\r\nHost: 5.5.5.5\r\nConnection: close\r\n\r\n")
    probe = socket.fromfd(ssock.fileno(), socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(3)
    try:
        while True:
            data = probe.recv(2048)
            if not data:
                raise SystemExit("foreign seat closed with FIN, Moonlight would keep this address")
    except ConnectionResetError:
        return
    finally:
        try:
            probe.close()
        except OSError:
            pass
        try:
            ssock.close()
        except OSError:
            pass


