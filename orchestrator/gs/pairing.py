"""Sunshine's four pairing phases, PIN included, then pairchallenge."""
import secrets
import socket
import ssl
import time
import urllib.parse
import uuid
from hashlib import sha256

from gs.protocol import (
    HTTPS_PORT,
    PIN_WAIT,
    SUNSHINE_HTTP,
    _request,
    _write_temp,
    aes_ecb,
    aes_key,
    canonical_pem,
    cert_signature,
    fail_xml,
    fingerprint,
    hx,
    log,
    parse_xml,
    sign256,
    unhex,
    verify256,
    xml_response,
)

class PairServer:
    """Sunshine's four pairing phases. The PIN is typed on /pair by the
    user who is already signed in. The pending client is the certificate
    that is waiting, and the PIN is what proves this person can see that
    client. A second user pairing at the same time has a different client
    and a different PIN."""

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


def claim_pin(store, uid, pin, gsuser):
    """Bind this signed-in user to the client that is waiting on `uid`.

    The form does not get to choose the user. A PIN already accepted for
    a different user is left alone, so two people cannot take the same
    client. Returns "" on success, otherwise a short reason.
    """
    pin = (pin or "").strip()
    if not pin.isdigit() or len(pin) != 4:
        return "pin"
    if not uid or not gsuser:
        return "missing"
    result = {"err": "none"}

    def save(data):
        rec = (data.get("pending") or {}).get(uid)
        if not rec or rec.get("phase") != "wait-pin":
            return
        owner = rec.get("gsuser") or ""
        if rec.get("pin") and owner and owner != gsuser:
            result["err"] = "taken"
            return
        rec["pin"] = pin
        rec["gsuser"] = gsuser
        result["err"] = ""

    store.update(save)
    return result["err"]


def unpair_own(store, gsuser, fingerprint):
    """Drop one certificate, and only if it is already this user's."""
    if not gsuser or not fingerprint:
        return False
    removed = {"ok": False}

    def save(data):
        kept = []
        for client in data.get("clients") or []:
            if client.get("fingerprint") == fingerprint and client.get("gsuser") == gsuser:
                removed["ok"] = True
                continue
            kept.append(client)
        data["clients"] = kept

    store.update(save)
    return removed["ok"]


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

