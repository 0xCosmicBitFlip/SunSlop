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
client has moved. Those two are not forwarded here. `gs-relay` owns the
sockets. This process tells it which pod a client address belongs to.
"""

import hmac
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
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

    SSLSocket has no `_sock` in current CPython, and closing it sends
    close_notify (a FIN). detach() drops the TLS object without that
    shutdown; the kernel socket is then closed with SO_LINGER 0.
    """
    import struct
    try:
        fd = sock.detach()
    except Exception:
        fd = None
    if isinstance(fd, int) and fd >= 0:
        try:
            raw = socket.socket(fileno=fd)
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            raw.close()
            return
        except OSError:
            try:
                os.close(fd)
            except OSError:
                pass
            return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


_HOST_OK = re.compile(r"^[A-Za-z0-9._-]+$")
_HOST_V6 = re.compile(r"^\[[0-9A-Fa-f:.]+\]$")
_SESSION_URL = re.compile(r"(rtsp(?:enc)?://)(\[[^\]]+\]|[^/:]+)(:\d+)")


def host_only(value):
    """Host header without the port. Bracketed IPv6 keeps its brackets."""
    host = (value or "").strip()
    if not host:
        return ""
    if host.startswith("["):
        end = host.find("]")
        return host[:end + 1] if end > 1 else ""
    if host.count(":") == 1:
        name, port = host.split(":", 1)
        if port.isdigit():
            return name
    return host


def safe_host(value):
    host = host_only(value)
    if _HOST_OK.match(host) or _HOST_V6.match(host):
        return host
    return ""


def facing_host(raw, sock):
    """Address the client put in Host, else the local address it reached.

    Moonlight's Host is the computer it dialed. Sunshine's own answer uses
    the pod IP, which the client would store as LocalIP and open RTSP to.
    """
    text = raw.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", "replace")
    for line in text.split("\r\n")[1:]:
        if line.lower().startswith("host:"):
            host = safe_host(line.split(":", 1)[1])
            if host:
                return host
            break
    return _sock_ip(sock)


def rewrite_backend_response(raw, host, uniqueid):
    """Sunshine answered from the pod. Put the client's host back.

    LocalIP is what Moonlight stores and polls next (Android tries it
    first). sessionUrl0 is the RTSP url; current moonlight-common-c dials
    the active address but uses this host in the RTSP request. uniqueid is
    the computer id. The seat has its own, and a later poll must not look
    like a different PC from the serverinfo this proxy already sent.
    """
    host = safe_host(host)
    if not raw or not host or b"\r\n\r\n" not in raw:
        return raw
    head, _, body = raw.partition(b"\r\n\r\n")
    if b"<" not in body:
        return raw
    text = body.decode("utf-8", "replace")
    text = re.sub(
        r"(<LocalIP>)[^<]*(</LocalIP>)",
        lambda m: m.group(1) + host + m.group(2),
        text,
    )
    if uniqueid and re.fullmatch(r"[A-Za-z0-9-]+", uniqueid):
        text = re.sub(
            r"(<uniqueid>)[^<]*(</uniqueid>)",
            lambda m: m.group(1) + uniqueid + m.group(2),
            text,
        )
    text = _SESSION_URL.sub(lambda m: m.group(1) + host + m.group(3), text)
    new_body = text.encode("utf-8")
    lines = []
    saw_length = False
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            lines.append(b"Content-Length: " + str(len(new_body)).encode())
            saw_length = True
        else:
            lines.append(line)
    if not saw_length:
        lines.append(b"Content-Length: " + str(len(new_body)).encode())
    return b"\r\n".join(lines) + b"\r\n\r\n" + new_body


def relay_ipv4(value):
    parts = (value or "").split(".")
    if len(parts) != 4:
        return ""
    try:
        nums = [int(part) for part in parts]
    except ValueError:
        return ""
    if any(num < 0 or num > 255 for num in nums):
        return ""
    if any(part != str(num) for part, num in zip(parts, nums)):
        return ""
    return ".".join(str(num) for num in nums)


def relay_user(value):
    if not value or len(value) > 64:
        return ""
    if any(ch.isspace() or ord(ch) < 32 for ch in value):
        return ""
    return value


def _relay_sources(root):
    newest = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name != "target"]
        for name in filenames:
            if name.endswith((".rs", ".toml", ".lock")):
                newest = max(newest, os.path.getmtime(os.path.join(dirpath, name)))
    return newest


def relay_source_dir():
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gs-relay")
    packaged = "/usr/local/src/gs-relay"
    for path in (here, packaged):
        if os.path.isfile(os.path.join(path, "Cargo.toml")):
            return path
    return ""


def ensure_relay_binary():
    """The binary the proxy will exec. Pods compile it before this process."""
    override = os.environ.get("GS_RELAY_BIN", "").strip()
    if override:
        if not os.path.isfile(override) or not os.access(override, os.X_OK):
            raise SystemExit(f"GS_RELAY_BIN is not executable: {override}")
        return override
    installed = "/usr/local/bin/gs-relay"
    if os.path.isfile(installed) and os.access(installed, os.X_OK):
        return installed
    src = relay_source_dir()
    built = os.path.join(src, "target", "release", "gs-relay") if src else ""
    if built and os.path.isfile(built) and os.access(built, os.X_OK):
        if _relay_sources(src) <= os.path.getmtime(built):
            return built
    if not src or not shutil_which("cargo"):
        raise SystemExit("gs-relay is not built; the proxy compiles it on start")
    log(f"compiling gs-relay in {src}")
    subprocess.check_call(
        ["cargo", "build", "--release", "--offline", "--locked"],
        cwd=src,
    )
    if not os.path.isfile(built):
        raise SystemExit("gs-relay compile did not produce a binary")
    return built


def shutil_which(name):
    path = os.environ.get("PATH", "")
    for directory in path.split(os.pathsep):
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


class RustRelay:
    """Child process that owns the UDP sockets and the RTSP splice.

    `map` is the only thing Python has to say: this client address goes to
    that pod. `touch` comes back when forwarded bytes should keep the seat.
    """

    def __init__(self, ports, rtsp_wait, touch, bind="0.0.0.0"):
        self.ports = ports
        self.rtsp_wait = int(rtsp_wait)
        self.touch = touch
        self.bind = bind
        self.proc = None
        self.sock = None
        self._write_lock = threading.Lock()
        self._map_mu = threading.Lock()
        self._ack = threading.Event()
        self._stopping = False
        self._dir = ""

    def start(self):
        binary = ensure_relay_binary()
        self._dir = tempfile_dir()
        path = os.path.join(self._dir, "control.sock")
        udp = ",".join(str(port) for port in self.ports["udp"])
        cmd = [
            binary,
            "--control", path,
            "--udp", udp,
            "--rtsp", str(self.ports["rtsp"]),
            "--rtsp-wait", str(self.rtsp_wait),
            "--bind", self.bind,
        ]
        self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL)
        try:
            self._connect(path)
        except BaseException:
            self._stopping = True
            self._kill()
            raise
        threading.Thread(target=self._read, name="gs-relay-read", daemon=True).start()
        threading.Thread(target=self._watch, name="gs-relay-watch", daemon=True).start()

    def _connect(self, path):
        deadline = time.time() + 10
        last = "did not listen"
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise SystemExit(f"gs-relay exited {self.proc.returncode}")
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(path)
            except OSError as exc:
                last = str(exc)
                time.sleep(0.05)
                continue
            sock.settimeout(5)
            buf = b""
            try:
                while b"\n" not in buf:
                    chunk = sock.recv(128)
                    if not chunk:
                        break
                    buf += chunk
            except OSError as exc:
                last = str(exc)
                sock.close()
                time.sleep(0.05)
                continue
            if not buf.startswith(b"ready\n") and buf.strip() != b"ready":
                sock.close()
                raise SystemExit(f"gs-relay handshake {buf!r}")
            sock.settimeout(None)
            self.sock = sock
            return
        raise SystemExit(f"gs-relay control socket: {last}")

    def _watch(self):
        code = self.proc.wait()
        if self._stopping:
            return
        log(f"gs-relay exited {code}")
        os._exit(1)

    def _read(self):
        buf = b""
        while not self._stopping:
            try:
                chunk = self.sock.recv(4096)
            except OSError:
                return
            if not chunk:
                return
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                self._event(line.decode("utf-8", "replace").strip())

    def _event(self, line):
        if line == "ok":
            self._ack.set()
            return
        if line.startswith("touch "):
            user = relay_user(line[6:])
            if not user:
                return
            try:
                self.touch(user)
            except Exception as exc:
                log(f"touch {user}: {exc}")
        elif line.startswith("log "):
            log(line[4:])

    def map(self, client_ip, pod_ip, user):
        client = relay_ipv4(client_ip)
        pod = relay_ipv4(pod_ip)
        name = relay_user(user)
        if not client or not pod or not name:
            log(f"gs-relay map rejected client={client_ip!r} pod={pod_ip!r} user={user!r}")
            return
        # The old in-process dict was visible to UDP as soon as _remember
        # returned. Wait until the relay has installed the same row.
        with self._map_mu:
            self._ack.clear()
            self._send(f"map {client} {pod} {name}\n")
            if not self._ack.wait(2):
                log(f"gs-relay did not acknowledge map for {client}")

    def _send(self, text):
        data = text.encode()
        with self._write_lock:
            sock = self.sock
            if sock is None:
                return
            try:
                sock.sendall(data)
            except OSError as exc:
                log(f"gs-relay map: {exc}")

    def _kill(self):
        proc = self.proc
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1)

    def stop(self):
        self._stopping = True
        self._kill()
        sock = self.sock
        self.sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if self._dir:
            import shutil
            shutil.rmtree(self._dir, ignore_errors=True)
            self._dir = ""


def tempfile_dir():
    import tempfile
    return tempfile.mkdtemp(prefix="gs-relay-")


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
        b"<LocalIP>10.9.9.9</LocalIP><currentgame>7</currentgame>"
        b"<sessionUrl0>rtsp://10.9.9.9:48010</sessionUrl0>"
        b"<sessionUrl1>rtspenc://10.9.9.9:48010</sessionUrl1></root>",
        b"application/xml",
    )
    rewritten = rewrite_backend_response(sample, "5.5.5.5:47984", "proxyuid")
    assert b"<LocalIP>5.5.5.5</LocalIP>" in rewritten
    assert b"<uniqueid>proxyuid</uniqueid>" in rewritten
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

    seat_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "image", "seat-boot.py")
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


if __name__ == "__main__":
    self_test()
