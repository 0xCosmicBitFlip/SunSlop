"""Moonlight wire codec: pairing crypto, serverinfo XML, address rewrite."""
import os
import re
import socket
import time
from hashlib import sha256
import xml.etree.ElementTree as ET

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


def server_mac(uniqueid):
    """Stable mac Moonlight stores next to uniqueid. Same inputs, same mac."""
    digest = sha256((uniqueid or "").encode()).digest()
    return "02:" + ":".join(f"{b:02x}" for b in digest[:5])


def serverinfo_xml(paired, uniqueid, local_ip, https=False, http_port=SUNSHINE_HTTP,
                   https_port=HTTPS_PORT, external_ip=""):
    mac = server_mac(uniqueid) if https else "00:00:00:00:00:00"
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
    first). ExternalIP is the address it keeps as the remote one, so a
    pod address there would be dialed later. sessionUrl0 is the RTSP url;
    current moonlight-common-c dials the active address but uses this host
    in the RTSP request. uniqueid is the computer id Android requires.
    The mac is stored beside it; the seat's own mac would replace the one
    this proxy already advertised.
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
    text = re.sub(
        r"(<ExternalIP>)[^<]*(</ExternalIP>)",
        lambda m: m.group(1) + host + m.group(2),
        text,
    )
    if uniqueid and re.fullmatch(r"[A-Za-z0-9-]+", uniqueid):
        text = re.sub(
            r"(<uniqueid>)[^<]*(</uniqueid>)",
            lambda m: m.group(1) + uniqueid + m.group(2),
            text,
        )
        mac = server_mac(uniqueid)
        text = re.sub(
            r"(<mac>)[^<]*(</mac>)",
            lambda m: m.group(1) + mac + m.group(2),
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

