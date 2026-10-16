"""Talk to the gs-relay process. Python does not bind the UDP ports."""
import os
import socket
import subprocess
import tempfile
import threading
import time

from gs.protocol import log

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
    # This file is gs/relay.py. The crate is orchestrator/gs-relay, or the
    # image copy at /usr/local/src/gs-relay. __file__ is not next to the crate.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    here = os.path.join(root, "gs-relay")
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

