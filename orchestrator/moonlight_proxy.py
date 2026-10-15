#!/usr/bin/env python3
"""Moonlight-facing proxy.

Clients pair with this process, not with a seat. Moonlight's four pairing
phases are plain HTTP on the configured Sunshine base. The follow-up
pairchallenge, and every later control call, is TLS on the HTTPS port. The
client certificate selects a login. If the seat is down the request is held
until it is up, then a second TLS session to the pod presents the shared
proxy certificate. That certificate is generated once, on the persist
volume, and the seat boot script installs it into sunshine_state.json.

A seat on another node is not spliced. Selkies is HTTP to a browser, so that
proxy answers 307 and the browser moves. Moonlight's control channel is HTTP
too, and current clients follow a 307, but the stream does not: RTSP and UDP
are opened to the address that answered, not to the Location host. A 307
would pin the stream to this proxy. What Moonlight stores and retries is
LocalIP and ExternalIP inside serverinfo. `HTTP_FOREIGN=redirect` (the
default) answers one serverinfo with the owning proxy's address, then RSTs
so the next poll fails here and succeeds there. `HTTP_FOREIGN=reset` RSTs
immediately. UDP and RTSP have no redirect; they arrive only after the
client has moved.
"""

import hmac
import json
import os
import secrets
import socket
import ssl
import threading
import time
import uuid
import urllib.parse
import xml.etree.ElementTree as ET
from hashlib import sha256

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID

# Offsets from Sunshine's HTTP base. These are the protocol, not site config.
# The base itself is cfg.sunshine_base (SUNSHINE_BASE in the deploy ConfigMap).
# A deploy can pass the same offsets through the ConfigMap; ports_for uses them.
HTTPS_OFFSET = -5
WEB_OFFSET = 1
RTSP_OFFSET = 21
UDP_OFFSETS = (9, 10, 11, 13, 21)
SUNSHINE_HTTP = 47989
HTTPS_PORT = SUNSHINE_HTTP + HTTPS_OFFSET
RTSP_PORT = SUNSHINE_HTTP + RTSP_OFFSET
UDP_PORTS = tuple(SUNSHINE_HTTP + off for off in UDP_OFFSETS)


def ports_for(base, https_offset=HTTPS_OFFSET, web_offset=WEB_OFFSET,
              rtsp_offset=RTSP_OFFSET, udp_offsets=UDP_OFFSETS):
    base = int(base)
    return {
        "http": base,
        "https": base + int(https_offset),
        "web": base + int(web_offset),
        "rtsp": base + int(rtsp_offset),
        "udp": tuple(base + int(off) for off in udp_offsets),
    }


PIN_WAIT = 600

try:
    import fcntl
except ImportError:
    fcntl = None


def log(msg):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(f"{ts} moonlight {msg}", flush=True)


def aes_key(salt, pin):
    return sha256(salt + pin.encode()).digest()[:16]


def aes_ecb(key, data, decrypt=False):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    ctx = cipher.decryptor() if decrypt else cipher.encryptor()
    return ctx.update(data) + ctx.finalize()


def cert_signature(pem):
    return x509.load_pem_x509_certificate(_pem(pem)).signature


def sign256(key_pem, data):
    key = serialization.load_pem_private_key(_pem(key_pem), password=None)
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def verify256(cert_pem, data, sig):
    try:
        x509.load_pem_x509_certificate(_pem(cert_pem)).public_key().verify(
            sig, data, padding.PKCS1v15(), hashes.SHA256()
        )
        return True
    except Exception:
        return False


def _pem(value):
    if isinstance(value, str):
        value = value.encode()
    return value


def canonical_pem(data):
    raw = _pem(data)
    if b"-----BEGIN" in raw:
        cert = x509.load_pem_x509_certificate(raw)
    else:
        cert = x509.load_der_x509_certificate(raw)
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def fingerprint(pem):
    der = x509.load_pem_x509_certificate(_pem(pem)).public_bytes(serialization.Encoding.DER)
    return sha256(der).hexdigest()


def make_cert(cn):
    from datetime import datetime, timedelta, timezone
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem.decode(), key_pem.decode()


def hx(data):
    return data.hex()


def unhex(text):
    return bytes.fromhex(text.strip())


def xml_response(fields, status=200):
    root = ET.Element("root", status_code=str(status))
    for key, value in fields.items():
        ET.SubElement(root, key).text = str(value)
    body = b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" + ET.tostring(root)
    return http_response(body, b"application/xml", status)


def http_response(body, content_type, status=200, extra=b""):
    reason = b"OK" if status == 200 else b"ERR"
    return (
        b"HTTP/1.1 " + str(status).encode() + b" " + reason + b"\r\n"
        b"Content-Type: " + content_type + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: keep-alive\r\n" + extra + b"\r\n" + body
    )


def moonlight_foreign(mode, host, info, path, already_pointed):
    """Moonlight control request for a seat that is not on this node.

    splice: relay to the pod. Only when HTTP_FOREIGN=proxy and the pod IP
    is already known.
    point: answer serverinfo with LocalIP and ExternalIP set to `host`.
    That is the address desktop and Android store and poll next.
    reset: RST this attempt. The poll of this address fails, so the client
    tries the address from the serverinfo it already stored.

    A 307 is not sent. Qt 6 and OkHttp would follow it for this one call and
    then still open the stream to the address they already had.
    """
    mode = (mode or "redirect").lower()
    if mode == "proxy" and info:
        return "splice"
    if mode == "reset" or not host:
        return "reset"
    if path == "/serverinfo" and not already_pointed:
        return "point"
    return "reset"


def parse_xml(text):
    root = ET.fromstring(text)
    out = dict(root.attrib)
    for child in root:
        out[child.tag] = child.text or ""
    return out


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
        tmp = self.cert_path + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.cert_path)
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


def serverinfo_xml(paired, uniqueid, local_ip, https=False, http_port=SUNSHINE_HTTP,
                   https_port=HTTPS_PORT, external_ip=""):
    if https:
        digest = sha256(uniqueid.encode()).digest()
        mac = "02:" + ":".join(f"{b:02x}" for b in digest[:5])
    else:
        mac = "00:00:00:00:00:00"
    fields = {
        "hostname": "gs-proxy",
        "appversion": "7.1.431.-1",
        "GfeVersion": "3.23.0.74",
        "uniqueid": uniqueid,
        "HttpsPort": https_port,
        "ExternalPort": http_port,
        "mac": mac,
        "LocalIP": local_ip,
        "PairStatus": 1 if paired else 0,
        "currentgame": 0,
        "state": "SUNSHINE_SERVER_FREE",
        "ServerCodecModeSupport": 65793,
        "MaxLumaPixelsHEVC": 1869449984,
    }
    if external_ip:
        fields["ExternalIP"] = external_ip
    return xml_response(fields)


def fail_xml(message):
    root = ET.Element("root", status_code="400", status_message=message, paired="0")
    body = b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" + ET.tostring(root)
    return http_response(body, b"application/xml", 200)


class PairServer:
    """Sunshine's four pairing phases, with the PIN filled in from the admin UI."""

    def __init__(self, store):
        self.store = store

    def handle(self, query, server_cert, server_key):
        phrase = query.get("phrase", [""])[0]
        if phrase == "pairchallenge":
            return xml_response({"paired": 1})
        uid = query.get("uniqueid", [""])[0]
        if not uid:
            return fail_xml("missing uniqueid")
        if phrase == "getservercert" or "salt" in query and "clientcert" in query:
            return self._phase1(uid, query, server_cert)
        if "clientchallenge" in query:
            return self._phase2(uid, query.get("clientchallenge", [""])[0], server_cert)
        if "serverchallengeresp" in query:
            return self._phase3(uid, query.get("serverchallengeresp", [""])[0], server_key)
        if "clientpairingsecret" in query:
            return self._phase4(uid, query.get("clientpairingsecret", [""])[0])
        return fail_xml("unknown pair request")

    def _session(self, uid):
        pending = self.store.snapshot()["pending"]
        return pending.get(uid)

    def _phase1(self, uid, query, server_cert):
        salt_hex = query.get("salt", [""])[0]
        cert_hex = query.get("clientcert", [""])[0]
        name = query.get("devicename", ["moonlight"])[0][:64]
        try:
            pem = canonical_pem(unhex(cert_hex))
        except Exception as exc:
            return fail_xml(f"bad client cert: {exc}")

        def add(data):
            cutoff = int(time.time()) - PIN_WAIT
            data["pending"] = {
                k: v for k, v in data["pending"].items() if v.get("created", 0) >= cutoff
            }
            data["pending"][uid] = {
                "uniqueid": uid,
                "name": name,
                "salt": salt_hex,
                "client_cert": pem,
                "fingerprint": fingerprint(pem),
                "created": int(time.time()),
                "pin": "",
                "gsuser": "",
                "phase": "wait-pin",
            }
        self.store.update(add)
        pin, gsuser = self._wait_pin(uid, PIN_WAIT)
        if not pin:
            return fail_xml("pin timeout")
        try:
            key = aes_key(unhex(salt_hex)[:16], pin)
        except Exception as exc:
            return fail_xml(f"bad salt: {exc}")

        def save(data):
            rec = data["pending"].get(uid)
            if rec:
                rec["phase"] = "getservercert"
                rec["key"] = hx(key)
                rec["pin"] = pin
                rec["gsuser"] = gsuser
        self.store.update(save)
        return xml_response({"paired": 1, "plaincert": hx(server_cert.encode())})

    def _wait_pin(self, uid, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            rec = self._session(uid) or {}
            if rec.get("pin") and rec.get("gsuser"):
                return rec["pin"], rec["gsuser"]
            time.sleep(0.4)
        return None, None

    def _phase2(self, uid, challenge_hex, server_cert):
        rec = self._session(uid)
        if not rec or rec.get("phase") != "getservercert":
            return fail_xml("out of order")
        key = unhex(rec["key"])
        decrypted = aes_ecb(key, unhex(challenge_hex), decrypt=True)
        server_secret = secrets.token_bytes(16)
        server_challenge = secrets.token_bytes(16)
        signed = cert_signature(server_cert)
        digest = sha256(decrypted + signed + server_secret).digest()
        encrypted = aes_ecb(key, digest + server_challenge)

        def save(data):
            rec2 = data["pending"].get(uid)
            if rec2:
                rec2["phase"] = "clientchallenge"
                rec2["server_secret"] = hx(server_secret)
                rec2["server_challenge"] = hx(server_challenge)
        self.store.update(save)
        return xml_response({"paired": 1, "challengeresponse": hx(encrypted)})

    def _phase3(self, uid, response_hex, server_key):
        rec = self._session(uid)
        if not rec or rec.get("phase") != "clientchallenge":
            return fail_xml("out of order")
        key = unhex(rec["key"])
        client_hash = aes_ecb(key, unhex(response_hex), decrypt=True)
        secret = unhex(rec["server_secret"])
        signature = sign256(server_key, secret)

        def save(data):
            rec2 = data["pending"].get(uid)
            if rec2:
                rec2["phase"] = "serverchallengeresp"
                rec2["client_hash"] = hx(client_hash)
        self.store.update(save)
        return xml_response({"paired": 1, "pairingsecret": hx(secret + signature)})

    def _phase4(self, uid, secret_hex):
        rec = self._session(uid)
        if not rec or rec.get("phase") != "serverchallengeresp":
            return fail_xml("out of order")
        blob = unhex(secret_hex)
        if len(blob) <= 16:
            return fail_xml("short secret")
        client_secret, sig = blob[:16], blob[16:]
        expected = sha256(
            unhex(rec["server_challenge"]) + cert_signature(rec["client_cert"]) + client_secret
        ).digest()
        ok = expected == unhex(rec["client_hash"]) and verify256(rec["client_cert"], client_secret, sig)
        if not ok:
            return xml_response({"paired": 0})

        def commit(data):
            data["clients"] = [c for c in data["clients"] if c.get("fingerprint") != rec["fingerprint"]]
            data["clients"].append({
                "name": rec["name"],
                "gsuser": rec["gsuser"],
                "cert": rec["client_cert"],
                "fingerprint": rec["fingerprint"],
                "uuid": rec["uniqueid"],
            })
            data["pending"].pop(uid, None)
        self.store.update(commit)
        log(f"paired {rec['name']} as {rec['gsuser']}")
        return xml_response({"paired": 1})


def client_pair(host, pin, cert_pem, key_pem, http_port=SUNSHINE_HTTP, https_port=HTTPS_PORT):
    """Pair this certificate the way Moonlight does.

    Phases 1-4 are HTTP on the Sunshine base port and block in phase 1 until
    `pin` is entered on that Sunshine. phrase=pairchallenge is then HTTPS.
    """
    salt = secrets.token_bytes(16)
    uid = uuid.uuid4().hex
    last_exc = None
    raw = None
    for _ in range(20):
        try:
            raw = socket.create_connection((host, http_port), timeout=10)
            break
        except OSError as exc:
            last_exc = exc
            time.sleep(2)
    if raw is None:
        return False, f"connect {host}:{http_port}: {last_exc}"
    raw.settimeout(PIN_WAIT + 30)
    try:
        query = urllib.parse.urlencode({
            "uniqueid": uid,
            "devicename": "gs-proxy",
            "updateState": "1",
            "phrase": "getservercert",
            "salt": hx(salt),
            "clientcert": hx(cert_pem.encode()),
        })
        status, xml = _request(raw, "/pair?" + query)
        if xml.get("paired") != "1" or not xml.get("plaincert"):
            return False, f"phase1 {status} {xml.get('status_message', '')}"
        server_cert = unhex(xml["plaincert"])
        try:
            server_pem = canonical_pem(server_cert)
        except Exception:
            server_pem = server_cert.decode("utf-8", "replace")
        key = aes_key(salt, pin)
        challenge = secrets.token_bytes(16)
        enc = aes_ecb(key, challenge)
        _, xml = _request(raw, "/pair?" + urllib.parse.urlencode({
            "uniqueid": uid, "devicename": "gs-proxy", "updateState": "1",
            "clientchallenge": hx(enc),
        }))
        if not xml.get("challengeresponse"):
            return False, "phase2"
        resp = aes_ecb(key, unhex(xml["challengeresponse"]), decrypt=True)
        server_hash, server_challenge = resp[:32], resp[32:48]
        client_secret = secrets.token_bytes(16)
        client_hash = sha256(server_challenge + cert_signature(cert_pem) + client_secret).digest()
        _, xml = _request(raw, "/pair?" + urllib.parse.urlencode({
            "uniqueid": uid, "devicename": "gs-proxy", "updateState": "1",
            "serverchallengeresp": hx(aes_ecb(key, client_hash)),
        }))
        if not xml.get("pairingsecret"):
            return False, "phase3"
        blob = unhex(xml["pairingsecret"])
        server_secret, server_sig = blob[:16], blob[16:]
        expect = sha256(challenge + cert_signature(server_pem) + server_secret).digest()
        if expect != server_hash or not verify256(server_pem, server_secret, server_sig):
            return False, "server auth failed"
        secret_sig = sign256(key_pem, client_secret)
        _, xml = _request(raw, "/pair?" + urllib.parse.urlencode({
            "uniqueid": uid, "devicename": "gs-proxy", "updateState": "1",
            "clientpairingsecret": hx(client_secret + secret_sig),
        }))
        if xml.get("paired") != "1":
            return False, "phase4 rejected"
    finally:
        try:
            raw.close()
        except OSError:
            pass

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(_write_temp(cert_pem), _write_temp(key_pem))
    ssock = None
    try:
        tls = socket.create_connection((host, https_port), timeout=15)
        ssock = ctx.wrap_socket(tls, server_hostname="sunshine")
        ssock.settimeout(15)
        _, xml = _request(ssock, "/pair?" + urllib.parse.urlencode({
            "uniqueid": uid,
            "devicename": "gs-proxy",
            "updateState": "1",
            "phrase": "pairchallenge",
        }))
    except (OSError, ssl.SSLError) as exc:
        return False, f"pairchallenge: {exc}"
    finally:
        if ssock is not None:
            try:
                ssock.close()
            except OSError:
                pass
    if xml.get("paired") != "1":
        return False, "pairchallenge rejected"
    return True, "paired"


_temps = []


def _write_temp(pem):
    import tempfile
    fh = tempfile.NamedTemporaryFile(delete=False)
    fh.write(_pem(pem))
    fh.close()
    _temps.append(fh.name)
    return fh.name


def _request(ssock, path):
    raw = f"GET {path} HTTP/1.1\r\nHost: sunshine\r\nConnection: keep-alive\r\n\r\n".encode()
    ssock.sendall(raw)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = ssock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    length = 0
    status = 0
    for line in head.decode("iso-8859-1", "replace").split("\r\n"):
        if line.startswith("HTTP/"):
            status = int(line.split()[1])
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1].strip())
    while len(rest) < length:
        chunk = ssock.recv(4096)
        if not chunk:
            break
        rest += chunk
    body = rest[:length]
    if not body.strip():
        return status, {}
    return status, parse_xml(body.decode("utf-8", "replace"))


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
            for sock, how in ((src, socket.SHUT_RD), (dst, socket.SHUT_WR)):
                try:
                    sock.shutdown(how)
                except OSError:
                    pass

    a = threading.Thread(target=pump, args=(left, right), daemon=True)
    b = threading.Thread(target=pump, args=(right, left), daemon=True)
    a.start()
    b.start()
    a.join()
    b.join()


def read_http(sock, buf):
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            return None, buf
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    headers = head.decode("iso-8859-1", "replace").split("\r\n")
    length = 0
    for line in headers[1:]:
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1].strip())
    while len(rest) < length:
        chunk = sock.recv(65536)
        if not chunk:
            break
        rest += chunk
    raw = head + b"\r\n\r\n" + rest[:length]
    return raw, rest[length:]


def read_response(sock):
    return read_http(sock, b"")


def _sock_ip(sock):
    try:
        ip = sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    if not ip or ip == "0.0.0.0" or ":" in ip:
        return "127.0.0.1"
    return ip


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


def reset_tcp(sock):
    """RST the client. A TLS close_notify looks like a finished request, so
    Moonlight keeps this address. Linger-0 fails the poll of this address
    and the client tries the next one it stored.
    """
    import struct
    raw = sock
    seen = set()
    while raw is not None and id(raw) not in seen:
        seen.add(id(raw))
        nxt = getattr(raw, "_sock", None)
        if nxt is None or nxt is raw:
            break
        raw = nxt
    try:
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        raw.close()
    except OSError:
        pass


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
        self.by_flow = {}
        self._pointed = set()
        self._map_lock = threading.Lock()
        self._stop = threading.Event()

    def start(self):
        threading.Thread(target=self._tls_loop, name="moon-tls", daemon=True).start()
        threading.Thread(target=self._udp_loop, name="moon-udp", daemon=True).start()
        threading.Thread(target=self._game_http_loop, name="moon-http", daemon=True).start()
        threading.Thread(target=self._plain_loop, args=(self.ports["rtsp"],), name="moon-rtsp", daemon=True).start()
        log(f"tls :{self.ports['https']}, http :{self.ports['http']}, rtsp :{self.ports['rtsp']}, udp {self.ports['udp']}")

    def serve(self):
        self.start()
        self._stop.wait()

    def _remember(self, client_ip, pod_ip, gsuser, touch=True):
        with self._map_lock:
            self.by_ip[client_ip] = {"pod": pod_ip, "user": gsuser, "when": time.time()}
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
        try:
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
                        ssock.sendall(self.pairs.handle(query, cert, key))
                    continue
                client = self.store.client_for_der(peer)
                user = self.directory.get(client["gsuser"]) if client else None
                if parsed.path == "/serverinfo":
                    placed = self.seats.lookup(user) if user else None
                    kind = getattr(placed, "kind", "") if placed else ""
                    if kind == "remote":
                        if self._steer(ssock, user, placed, target, https=True):
                            return
                        target_ip, count = placed.info, False
                    elif kind != "local":
                        _c, _k, uid = self.store.server_material()
                        ssock.sendall(serverinfo_xml(
                            user is not None, uid, _sock_ip(ssock), https=True,
                            http_port=self.ports["http"], https_port=self.ports["https"],
                        ))
                        continue
                    else:
                        target_ip, count = placed.info, False
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
                ssock.sendall(resp)
        except (OSError, ssl.SSLError) as exc:
            log(f"tls {addr[0]}: {exc}")
        finally:
            for sock in (backend, conn):
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
            return ctx.wrap_socket(raw, server_hostname="sunshine")
        except (OSError, ssl.SSLError) as exc:
            log(f"{gsuser}: backend tls {exc}")
            return None

    def _udp_loop(self):
        socks = []
        for port in self.ports["udp"]:
            sock = self._bind(socket.SOCK_DGRAM, port)
            sock.settimeout(1.0)
            socks.append((port, sock))
        while not self._stop.is_set():
            for port, sock in socks:
                try:
                    data, who = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    continue
                self._udp(sock, port, data, who)

    def _udp(self, sock, port, data, who):
        with self._map_lock:
            flow = self.by_flow.get((who[0], port))
        if flow and who[0] == flow.get("pod"):
            client = flow.get("client")
            if client:
                try:
                    sock.sendto(data, client)
                    self.seats.touch(flow["user"])
                except OSError:
                    pass
            return
        mapped = self._lookup_ip(who[0])
        if not mapped:
            return
        with self._map_lock:
            self.by_flow[(mapped["pod"], port)] = {
                "pod": mapped["pod"], "client": who, "user": mapped["user"],
            }
        try:
            sock.sendto(data, (mapped["pod"], port))
            self.seats.touch(mapped["user"])
        except OSError as exc:
            log(f"udp {port}: {exc}")

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
                    conn.sendall(self.pairs.handle(query, cert, key))
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

    def _plain_loop(self, port):
        listen = self._bind(socket.SOCK_STREAM, port)
        listen.listen(64)
        listen.settimeout(1.0)
        while not self._stop.is_set():
            try:
                conn, addr = listen.accept()
            except socket.timeout:
                continue
            except OSError:
                continue
            threading.Thread(target=self._plain, args=(conn, addr, port), daemon=True).start()

    def _plain(self, conn, addr, port):
        back = None
        try:
            deadline = time.time() + max(30, self.cfg.ready_timeout)
            mapped = None
            while time.time() < deadline:
                mapped = self._lookup_ip(addr[0])
                if mapped:
                    break
                time.sleep(0.2)
            if not mapped:
                return
            back = socket.create_connection((mapped["pod"], port), timeout=10)
            self.seats.touch(mapped["user"])
            splice(conn, back, lambda: self.seats.touch(mapped["user"]))
        except OSError as exc:
            log(f"tcp {port}: {exc}")
        finally:
            for sock in (conn, back):
                if sock is None:
                    continue
                try:
                    sock.close()
                except OSError:
                    pass

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


def self_test():
    import tempfile
    key = aes_key(b"\x00" * 16, "1234")
    assert key == sha256(b"\x00" * 16 + b"1234").digest()[:16]
    blob = aes_ecb(key, b"0123456789abcdef")
    assert aes_ecb(key, blob, decrypt=True) == b"0123456789abcdef"
    store = Store(os.path.join(tempfile.mkdtemp(), "store.json"))
    assert os.path.isfile(store.cert_path)
    assert "BEGIN CERTIFICATE" in open(store.cert_path).read()
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
    _loopback()
    print("moonlight self-test ok")


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
        listen.settimeout(20)
        try:
            try:
                conn, _addr = listen.accept()
            except socket.timeout:
                listen.close()
                return
        except Exception:
            listen.close()
            return
        conn.settimeout(20)
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
        listen.settimeout(20)
        try:
            while True:
                try:
                    conn, _addr = listen.accept()
                except socket.timeout:
                    break
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
    threading.Thread(target=feed, daemon=True).start()
    cert, key = make_cert("proxy-loop")
    ok, detail = client_pair("127.0.0.1", "9999", cert, key, http_box[0], https_box[0])
    assert ok, detail
    saved = store.client_for_der(
        x509.load_pem_x509_certificate(cert.encode()).public_bytes(serialization.Encoding.DER)
    )
    assert saved and saved["gsuser"] == "gsuser9"


if __name__ == "__main__":
    self_test()
