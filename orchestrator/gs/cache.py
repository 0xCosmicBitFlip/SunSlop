"""Redis board for seat owners and heartbeats.

The server is stock Redis (or Valkey). This module is only the client.
Nothing is written to disk there: a restart of every Redis pod leaves the
board empty, and the orchestrators elect again from the pod list.

`redis://host:6379` talks to that address.
`redis+sentinel://host:26379/sunslop` asks Sentinel which pod is primary.
A replica answers READONLY, which is not a place to write an owner.
"""
import json
import socket
import threading
import urllib.parse

_KEY = __import__("re").compile(r"^[A-Za-z0-9_./-]{1,200}$")

# Older stamp loses. expect "-" is unconditional. Any other expect is the
# owner that must still be stored ('' if the key is missing).
_PUT = """
local raw = redis.call('GET', KEYS[1])
local stamp = tonumber(ARGV[1])
local expect = ARGV[2]
local payload = ARGV[3]
if raw then
  local obj = cjson.decode(raw)
  if stamp < tonumber(obj.t) then
    return 0
  end
  if expect ~= '-' then
    local owner = ''
    if type(obj.v) == 'table' and obj.v.owner then
      owner = tostring(obj.v.owner)
    end
    if owner ~= expect then
      return 0
    end
  end
elseif expect ~= '-' and expect ~= '' then
  return 0
end
redis.call('SET', KEYS[1], payload)
return 1
"""


class Conflict(Exception):
    pass


class CacheDown(Exception):
    pass


class RedisError(CacheDown):
    pass


def check_key(key):
    if not _KEY.match(key or "") or ".." in key:
        raise ValueError("bad key")
    return key


def encode(args):
    parts = [f"*{len(args)}\r\n".encode()]
    for arg in args:
        if isinstance(arg, int) and not isinstance(arg, bool):
            arg = str(arg).encode()
        elif isinstance(arg, str):
            arg = arg.encode()
        parts.append(f"${len(arg)}\r\n".encode())
        parts.append(arg)
        parts.append(b"\r\n")
    return b"".join(parts)


def _exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise CacheDown("redis closed")
        buf += chunk
    return buf


def read_resp(sock):
    line = b""
    while not line.endswith(b"\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise CacheDown("redis closed")
        line += chunk
    line = line[:-2]
    kind, rest = line[:1], line[1:]
    if kind == b"+":
        return rest.decode()
    if kind == b"-":
        raise RedisError(rest.decode())
    if kind == b":":
        return int(rest)
    if kind == b"$":
        n = int(rest)
        if n < 0:
            return None
        data = _exact(sock, n)
        _exact(sock, 2)
        return data
    if kind == b"*":
        n = int(rest)
        if n < 0:
            return None
        return [read_resp(sock) for _ in range(n)]
    raise RedisError("bad redis reply")


def _record(key, raw):
    if raw is None:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode()
    obj = json.loads(raw)
    return {"key": key, "value": obj["v"], "stamp": obj["t"]}


class KeyStore:
    """Same rules as the Redis script, for tests without a server."""

    def __init__(self):
        self._items = {}
        self._lock = threading.Lock()

    def put(self, key, value, stamp, expect_owner=None):
        check_key(key)
        stamp = float(stamp)
        with self._lock:
            cur = self._items.get(key)
            if cur is not None and stamp < cur["stamp"]:
                raise Conflict()
            if expect_owner is not None:
                current = "" if cur is None else (cur["value"].get("owner") or "")
                if current != expect_owner:
                    raise Conflict()
            self._items[key] = {"key": key, "value": dict(value), "stamp": stamp}
            return {"key": key, "value": dict(value), "stamp": stamp}

    def get(self, key):
        check_key(key)
        with self._lock:
            rec = self._items.get(key)
            if rec is None:
                return None
            return {"key": key, "value": dict(rec["value"]), "stamp": rec["stamp"]}

    def prefix(self, prefix):
        if not prefix or ".." in prefix:
            raise ValueError("bad prefix")
        with self._lock:
            return {
                key: {"key": key, "value": dict(rec["value"]), "stamp": rec["stamp"]}
                for key, rec in self._items.items()
                if key.startswith(prefix)
            }

    def delete(self, key):
        check_key(key)
        with self._lock:
            self._items.pop(key, None)


class RedisClient:
    def __init__(self, url):
        self.url = url

    def _parsed(self):
        parts = urllib.parse.urlsplit(self.url)
        if parts.scheme == "redis":
            return "direct", parts.hostname, parts.port or 6379, None
        if parts.scheme == "redis+sentinel":
            name = parts.path.strip("/") or "sunslop"
            return "sentinel", parts.hostname, parts.port or 26379, name
        raise CacheDown(f"bad cache url {self.url}")

    def _addrs(self, host, port):
        if not host:
            raise CacheDown("no cache address")
        try:
            infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except OSError as exc:
            raise CacheDown(str(exc)) from exc
        seen = []
        for info in infos:
            ip = info[4][0]
            item = (ip, port)
            if item not in seen:
                seen.append(item)
        if not seen:
            raise CacheDown("no cache address")
        return seen

    def _connect(self, host, port):
        return socket.create_connection((host, port), 3)

    def _master(self):
        kind, host, port, name = self._parsed()
        if kind == "direct":
            return host, port
        last = None
        for addr in self._addrs(host, port):
            try:
                sock = self._connect(addr[0], addr[1])
            except OSError as exc:
                last = exc
                continue
            try:
                sock.sendall(encode(["SENTINEL", "get-master-addr-by-name", name]))
                reply = read_resp(sock)
            finally:
                sock.close()
            if not reply or reply[0] is None:
                last = CacheDown("sentinel has no master")
                continue
            ip = reply[0].decode() if isinstance(reply[0], bytes) else reply[0]
            master_port = reply[1].decode() if isinstance(reply[1], bytes) else reply[1]
            return ip, int(master_port)
        raise CacheDown(str(last or "no sentinel"))

    def _round(self, args):
        host, port = self._master()
        try:
            sock = self._connect(host, port)
        except OSError as exc:
            raise CacheDown(str(exc)) from exc
        try:
            sock.sendall(encode(args))
            return read_resp(sock)
        finally:
            sock.close()

    def _call(self, args):
        try:
            return self._round(args)
        except RedisError as exc:
            if "READONLY" not in str(exc):
                raise
            return self._round(args)

    def put(self, key, value, stamp, expect_owner=None):
        check_key(key)
        payload = json.dumps({"v": value, "t": stamp}, separators=(",", ":"))
        expect = "-" if expect_owner is None else expect_owner
        code = self._call(["EVAL", _PUT, "1", key, str(stamp), expect, payload])
        if code != 1:
            raise Conflict()

    def get(self, key):
        check_key(key)
        raw = self._call(["GET", key])
        return _record(key, raw)

    def prefix(self, prefix):
        if not prefix or ".." in prefix:
            raise ValueError("bad prefix")
        host, port = self._master()
        try:
            sock = self._connect(host, port)
        except OSError as exc:
            raise CacheDown(str(exc)) from exc
        try:
            keys = []
            cursor = b"0"
            while True:
                sock.sendall(encode(["SCAN", cursor, "MATCH", prefix + "*", "COUNT", "200"]))
                reply = read_resp(sock)
                cursor = reply[0]
                for key in reply[1] or []:
                    if isinstance(key, bytes):
                        key = key.decode()
                    keys.append(key)
                if cursor in (b"0", "0", 0):
                    break
            if not keys:
                return {}
            sock.sendall(encode(["MGET", *keys]))
            values = read_resp(sock)
        finally:
            sock.close()
        out = {}
        for key, raw in zip(keys, values):
            rec = _record(key, raw)
            if rec is not None:
                out[key] = rec
        return out

    def delete(self, key):
        check_key(key)
        self._call(["DEL", key])


CacheClient = RedisClient


def self_test():
    store = KeyStore()
    store.put("orch/a", {"id": "a", "beat": 1}, 1)
    try:
        store.put("orch/a", {"id": "a", "beat": 0}, 0)
        raise SystemExit("older stamp was accepted")
    except Conflict:
        pass
    store.put("own/u", {"owner": "b"}, 2, expect_owner="")
    try:
        store.put("own/u", {"owner": "c"}, 3, expect_owner="")
        raise SystemExit("cas ignored the current owner")
    except Conflict:
        pass
    assert store.get("own/u")["value"]["owner"] == "b"

    class Sock:
        def __init__(self, data):
            self.data = data
            self.i = 0

        def recv(self, n):
            chunk = self.data[self.i:self.i + n]
            self.i += len(chunk)
            return chunk

    assert read_resp(Sock(b"+PONG\r\n")) == "PONG"
    assert read_resp(Sock(b"$-1\r\n")) is None
    assert read_resp(Sock(b"$3\r\nfoo\r\n")) == b"foo"
    assert read_resp(Sock(b"*2\r\n$1\r\na\r\n:2\r\n")) == [b"a", 2]
    raw = encode(["EVAL", "return 1", "1", "own/u"])
    assert raw.startswith(b"*4\r\n")
    print("cache self-test ok")
