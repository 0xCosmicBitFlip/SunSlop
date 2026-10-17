#!/usr/bin/env python3
"""Host hypervisor wrapper for nvkvm-kata seats.

Kata 4.1 turns the firmware annotation into -bios. OVMF Secure Boot does
not work that way: the code image has to be a read-only pflash and the
variable store a second, writable pflash. The variable store is per login,
copied once from the empty OVMF_VARS template (not the secboot template,
which would refuse this unsigned guest kernel).

The same wrapper attaches the TPU emulator. Its scratchpad is a file under
the login's persistent directory, so deleting the pod does not delete it.
Kata has no -device annotation. The seat puts sunslop.* tokens in
kernel_params, which this process can see on the QEMU argv, and the tokens
are ignored by the guest kernel.

This binary is hypervisor.path. It rewrites argv and execs the nvkvm shim.
Install and the shim.env keys are in docs/nvkvm-kata.md.
"""

import hashlib
import os
import shutil
import socket
import struct
import subprocess
import sys
import time

TPU_NAME = "org.sunslop.tpu"
TPU_BYTES = 1 << 20
TPU_MAX = 4096


def load_shim_env(path="/etc/nvkvm-kata/shim.env"):
    if not os.path.isfile(path):
        return
    with open(path) as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if not key.startswith(("NVKVM_", "GS_")):
                continue
            os.environ.setdefault(key, value.strip().strip('"').strip("'"))


def _token(argv, key):
    prefix = key + "="
    for arg in argv:
        for part in arg.split():
            if part.startswith(prefix):
                return part[len(prefix):]
    return ""


def _machine(value):
    parts = [part for part in value.split(",") if part and part != "nosmm" and part != "smm=off"]
    if not any(part == "smm=on" or part.startswith("smm=") for part in parts):
        parts.append("smm=on")
    return ",".join(parts)


def persist_roots(env):
    """HDD and SSD homes. GS_PERSIST_ROOT is accepted as a single root."""
    found = []
    for key in ("GS_PERSIST_HDD", "GS_PERSIST_SSD", "GS_PERSIST_ROOT"):
        val = (env.get(key) or "").strip()
        if val and val not in found:
            found.append(val)
    return found


def user_path(root, path, kind):
    """<root>/<login>/tpu or <root>/<login>/uefi/OVMF_VARS.fd. Nothing else.

    root may be one path or a list. A home is valid under either persist
    root. '..' is rejected in the raw string. abspath would hide it, and a
    seat annotation must name the directory it means.
    """
    roots = root if isinstance(root, (list, tuple)) else [root]
    for item in roots:
        got = _user_path(item, path, kind)
        if got:
            return got
    return ""


def _user_path(root, path, kind):
    root = (root or "").strip()
    if not root or not path or not path.startswith("/") or ".." in path.split("/"):
        return ""
    root = os.path.abspath(root)
    path = os.path.abspath(path)
    if not root or root == os.sep or os.path.commonpath([root, path]) != root:
        return ""
    rel = os.path.relpath(path, root)
    parts = rel.split(os.sep)
    if any(part in ("", ".", "..") for part in parts):
        return ""
    login = parts[0]
    if not login[0].isalpha() or not all(c.islower() or c.isdigit() or c == "-" for c in login):
        return ""
    if kind == "tpu" and len(parts) == 2 and parts[1] not in ("uefi",):
        return path
    if kind == "uefi" and parts == [login, "uefi", "OVMF_VARS.fd"]:
        return path
    return ""


def plan(argv, env):
    """Rewrite Kata's argv. Pure: it does not create files.

    Secure Boot that cannot be set up drops -bios instead of booting OVMF
    without a variable store. The TPU is omitted when its path is not the
    login directory under GS_PERSIST_HDD or GS_PERSIST_SSD.
    """
    roots = persist_roots(env)
    code = env.get("GS_UEFI_CODE", "")
    template = env.get("GS_UEFI_TEMPLATE", "")
    uefi = user_path(roots, _token(argv, "sunslop.uefi_vars"), "uefi")
    tpu = user_path(roots, _token(argv, "sunslop.tpu_state"), "tpu")
    secure = bool(uefi and code and template and os.path.isfile(code) and os.path.isfile(template))
    out = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "-bios" and index + 1 < len(argv):
            index += 2
            continue
        if arg == "-machine" and index + 1 < len(argv) and secure:
            out.extend(["-machine", _machine(argv[index + 1])])
            index += 2
            continue
        out.append(arg)
        index += 1
    if not secure:
        # Put -bios back if we were not asked to own firmware.
        if not uefi:
            return argv, "", tpu
        return out, "", tpu
    out.extend([
        "-drive", "if=pflash,format=raw,readonly=on,file=" + code,
        "-drive", "if=pflash,format=raw,file=" + uefi,
    ])
    return out, uefi, tpu


def ensure_vars(dest, template):
    parent = os.path.dirname(dest)
    os.makedirs(parent, 0o755, exist_ok=True)
    if os.path.exists(dest):
        return
    tmp = dest + ".tmp"
    shutil.copyfile(template, tmp)
    os.chmod(tmp, 0o644)
    os.replace(tmp, dest)


def tpu_socket(state, run_dir):
    digest = hashlib.sha256(state.encode()).hexdigest()[:16]
    return os.path.join(run_dir, digest + ".sock")


def tpu_devices(sock):
    return [
        "-chardev", "socket,id=tpu0,path=%s,reconnect-ms=200" % sock,
        "-device", "virtio-serial-pci,id=tpu-serial",
        "-device", "virtserialport,bus=tpu-serial.0,chardev=tpu0,name=%s" % TPU_NAME,
    ]


def _live(pid):
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _cmdline(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as handle:
            return handle.read().replace(b"\x00", b" ").decode("utf-8", "replace")
    except OSError:
        return ""


def reclaim_socket(sock):
    pid_path = sock + ".pid"
    pid = 0
    try:
        pid = int(open(pid_path).read().strip() or "0")
    except (OSError, ValueError):
        pid = 0
    if _live(pid) and "gs_kata_shim.py --tpu-serve" in _cmdline(pid):
        try:
            os.kill(pid, 15)
        except OSError:
            pass
        for _ in range(20):
            if not _live(pid):
                break
            time.sleep(0.05)
    for path in (sock, pid_path):
        try:
            os.unlink(path)
        except OSError:
            pass


class Tpu:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path), 0o755, exist_ok=True)
        self.fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        size = os.fstat(self.fd).st_size
        if size < TPU_BYTES:
            os.ftruncate(self.fd, TPU_BYTES)
            os.fsync(self.fd)

    def read(self, off, length):
        if length < 0 or length > TPU_MAX or off < 0 or off + length > TPU_BYTES:
            raise ValueError("range")
        os.lseek(self.fd, off, os.SEEK_SET)
        data = b""
        while len(data) < length:
            chunk = os.read(self.fd, length - len(data))
            if not chunk:
                break
            data += chunk
        if len(data) != length:
            raise ValueError("short")
        return data

    def write(self, off, data):
        if len(data) > TPU_MAX or off < 0 or off + len(data) > TPU_BYTES:
            raise ValueError("range")
        os.pwrite(self.fd, data, off)
        os.fsync(self.fd)

    def dot(self, a_off, b_off, count, dest):
        if count < 0 or count > TPU_MAX:
            raise ValueError("range")
        left = self.read(a_off, count)
        right = self.read(b_off, count)
        acc = 0
        for a, b in zip(left, right):
            acc += _i8(a) * _i8(b)
        acc &= 0xFFFFFFFF
        if acc >= 0x80000000:
            acc -= 0x100000000
        raw = struct.pack("<i", acc)
        self.write(dest, raw)
        return acc


def _i8(value):
    return value - 256 if value >= 128 else value


def _line(conn):
    buf = b""
    while b"\n" not in buf:
        got = conn.recv(1)
        if not got:
            return None
        buf += got
        if len(buf) > 128:
            return None
    return buf.decode("utf-8", "replace").strip()


def _exact(conn, length):
    buf = b""
    while len(buf) < length:
        got = conn.recv(length - len(buf))
        if not got:
            return None
        buf += got
    return buf


def handle(conn, tpu):
    while True:
        line = _line(conn)
        if line is None:
            return
        try:
            parts = line.split()
            op = parts[0] if parts else ""
            if op == "STAT" and len(parts) == 1:
                conn.sendall(b"OK %d\n" % TPU_BYTES)
            elif op == "READ" and len(parts) == 3:
                data = tpu.read(int(parts[1]), int(parts[2]))
                conn.sendall(b"OK %d\n" % len(data) + data)
            elif op == "WRITE" and len(parts) == 3:
                length = int(parts[2])
                if length < 0 or length > TPU_MAX:
                    raise ValueError("range")
                data = _exact(conn, length)
                if data is None:
                    return
                tpu.write(int(parts[1]), data)
                conn.sendall(b"OK\n")
            elif op == "DOT" and len(parts) == 5:
                acc = tpu.dot(int(parts[1]), int(parts[2]), int(parts[3]), int(parts[4]))
                conn.sendall(b"OK %d\n" % acc)
            else:
                conn.sendall(b"ERR cmd\n")
        except (ValueError, OSError):
            try:
                conn.sendall(b"ERR range\n")
            except OSError:
                return


def serve(ppid, state, sock):
    tpu = Tpu(os.path.join(state, "state.bin"))
    os.makedirs(os.path.dirname(sock), 0o755, exist_ok=True)
    reclaim_socket(sock)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock)
    os.chmod(sock, 0o600)
    server.listen(1)
    server.settimeout(1.0)
    with open(sock + ".pid", "w") as pid_file:
        pid_file.write(str(os.getpid()))
    while ppid <= 0 or _live(ppid):
        try:
            conn, _addr = server.accept()
        except socket.timeout:
            continue
        try:
            handle(conn, tpu)
        finally:
            conn.close()
    server.close()


def drop_pflash(argv):
    out = []
    index = 0
    while index < len(argv):
        if argv[index] == "-drive" and index + 1 < len(argv) and argv[index + 1].startswith("if=pflash"):
            index += 2
            continue
        out.append(argv[index])
        index += 1
    return out


def start_tpu(state, run_dir):
    os.makedirs(state, 0o755, exist_ok=True)
    os.makedirs(run_dir, 0o755, exist_ok=True)
    sock = tpu_socket(state, run_dir)
    proc = subprocess.Popen(
        [sys.executable, os.path.abspath(__file__), "--tpu-serve",
         "--ppid", str(os.getpid()), "--state", state, "--socket", sock]
    )
    deadline = time.time() + 2
    while time.time() < deadline:
        if proc.poll() is not None:
            return ""
        try:
            pid = int(open(sock + ".pid").read().strip() or "0")
        except (OSError, ValueError):
            pid = 0
        if pid == proc.pid and os.path.exists(sock):
            return sock
        time.sleep(0.02)
    return ""


def graphics_boot(argv, env):
    """nvkvm-steam uses the virtio-nvgpu DRM node as the display.

    An emulated VGA or a second virtio-gpu takes /dev/dri/card0, and labwc
    then never binds the NVIDIA device. GS_QEMU_VGA=keep leaves the argv alone.
    """
    mode = env.get("GS_QEMU_VGA", "none")
    if mode == "keep":
        return list(argv)
    drop = ("virtio-gpu", "virtio-vga", "VGA", "qxl", "bochs-display", "ramfb")
    out = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "-vga" and index + 1 < len(argv):
            index += 2
            continue
        if arg == "-device" and index + 1 < len(argv):
            device = argv[index + 1]
            if any(token in device for token in drop) and "nvgpu" not in device:
                index += 2
                continue
        out.append(arg)
        index += 1
    out.extend(["-vga", mode])
    return out


def sb_required(uefi, env):
    """GS_SB_ENFORCE=1 refuses the unsigned direct-kernel fallback."""
    return env.get("GS_SB_ENFORCE", "") == "1" and not uefi


def launch(argv):
    argv = graphics_boot(argv, os.environ)
    me = os.path.realpath(sys.argv[0])
    shim = os.environ.get("NVKVM_SHIM", "/opt/nvkvm-kata/bin/nvkvm-qemu-shim")
    if shim and os.path.realpath(shim) != me and os.access(shim, os.X_OK):
        os.execv(shim, [shim, *argv])
    qemu = os.environ.get("NVKVM_QEMU", "/opt/qemu-nvkvm/bin/qemu-system-x86_64")
    extra = os.environ.get(
        "NVKVM_EXTRA_ARGS", "-device virtio-nvgpu-pci-non-transitional,id=nvkvm0"
    ).split()
    os.execv(qemu, [qemu, *argv, *extra])


def main(argv):
    if argv[:1] == ["--self-test"]:
        _self_test()
        return 0
    if argv[:1] == ["--tpu-serve"]:
        opts = {}
        index = 1
        while index < len(argv):
            key = argv[index]
            if key.startswith("--") and index + 1 < len(argv):
                opts[key[2:]] = argv[index + 1]
                index += 2
                continue
            index += 1
        serve(int(opts.get("ppid", "0")), opts["state"], opts["socket"])
        return 0
    load_shim_env()
    env = dict(os.environ)
    rewritten, uefi, tpu = plan(argv, env)
    if _token(argv, "sunslop.uefi_vars") and not uefi:
        sys.stderr.write("gs-kata-shim: secure boot skipped\n")
    if uefi:
        try:
            ensure_vars(uefi, env["GS_UEFI_TEMPLATE"])
        except OSError as exc:
            sys.stderr.write("gs-kata-shim: uefi vars: %s\n" % exc)
            rewritten = drop_pflash(rewritten)
            uefi = ""
    if tpu:
        sock = start_tpu(tpu, env.get("GS_TPU_RUN", "/run/gs-tpu"))
        if sock:
            rewritten = rewritten + tpu_devices(sock)
            sys.stderr.write("gs-kata-shim: tpu %s\n" % tpu)
        else:
            sys.stderr.write("gs-kata-shim: tpu did not listen, seat has no TPU\n")
    if sb_required(uefi, env):
        sys.stderr.write(
            "gs-kata-shim: GS_SB_ENFORCE=1 but the signed variable store is not in use. "
            "Refusing to boot an unsigned kernel.\n"
        )
        return 1
    if uefi:
        sys.stderr.write("gs-kata-shim: secure boot vars %s\n" % uefi)
    launch(rewritten)
    return 127


def _client(sock, line, payload=b""):
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.connect(sock)
    conn.sendall(line.encode() + b"\n" + payload)
    buf = b""
    while b"\n" not in buf:
        buf += conn.recv(64)
    head, _, rest = buf.partition(b"\n")
    text = head.decode()
    if text.startswith("OK ") and line.startswith("READ"):
        need = int(text.split()[1])
        while len(rest) < need:
            rest += conn.recv(need - len(rest))
        conn.close()
        return text, rest
    conn.close()
    return text, rest


def _self_test():
    import tempfile
    root = tempfile.mkdtemp()
    code = os.path.join(root, "OVMF_CODE.secboot.fd")
    template = os.path.join(root, "OVMF_VARS.fd")
    open(code, "wb").write(b"CODE")
    open(template, "wb").write(b"VARS-EMPTY")
    env = {
        "GS_PERSIST_ROOT": root,
        "GS_UEFI_CODE": code,
        "GS_UEFI_TEMPLATE": template,
    }
    state = root + "/gsuser0/tpu"
    uefi = root + "/gsuser0/uefi/OVMF_VARS.fd"
    argv = [
        "-name", "sandbox-1",
        "-machine", "q35,accel=kvm,nosmm",
        "-bios", "/wrong/OVMF_CODE.fd",
        "-append", "quiet sunslop.tpu_state=%s sunslop.uefi_vars=%s sunslop.uefi_code=/wrong/OVMF_CODE.fd" % (state, uefi),
        "-kernel", "/opt/vmlinuz",
    ]
    rewritten, got_uefi, got_tpu = plan(argv, env)
    assert got_uefi == uefi
    assert got_tpu == state
    assert "-bios" not in rewritten
    machine = rewritten[rewritten.index("-machine") + 1]
    assert "nosmm" not in machine and "smm=on" in machine
    drives = [rewritten[i + 1] for i, arg in enumerate(rewritten) if arg == "-drive"]
    assert any(code in item and "readonly=on" in item for item in drives)
    assert any(item.endswith(uefi) and "readonly" not in item for item in drives)
    assert "-kernel" in rewritten
    bare, no_uefi, still_tpu = plan(["-bios", code, "-kernel", "vmlinuz"], env)
    assert bare == ["-bios", code, "-kernel", "vmlinuz"]
    assert no_uefi == "" and still_tpu == ""
    broken = dict(env)
    broken["GS_UEFI_TEMPLATE"] = root + "/missing"
    dropped, no_uefi, _tpu = plan(argv, broken)
    assert no_uefi == "" and "-bios" not in dropped
    for bad, kind in (
        (root + "/../etc/tpu", "tpu"),
        ("/tmp/gsuser0/tpu", "tpu"),
        (root + "/tpu", "tpu"),
        (root + "/Gsuser0/tpu", "tpu"),
        (root + "/gsuser0/uefi", "tpu"),
        (root + "/gsuser0/uefi/../../gsuser0/tpu", "tpu"),
        (root + "/gsuser0/uefi/evil.fd", "uefi"),
        (root + "/gsuser0/uefi/../uefi/OVMF_VARS.fd", "uefi"),
    ):
        assert user_path(root, bad, kind) == "", bad
    assert user_path(root, uefi, "uefi") == os.path.abspath(uefi)
    hdd = tempfile.mkdtemp()
    hdd_tpu = hdd + "/gsuser1/tpu"
    assert user_path([root, hdd], hdd_tpu, "tpu") == os.path.abspath(hdd_tpu)
    assert user_path([root], hdd_tpu, "tpu") == ""
    ensure_vars(uefi, template)
    assert open(uefi, "rb").read() == b"VARS-EMPTY"
    open(uefi, "wb").write(b"ENROLLED")
    ensure_vars(uefi, template)
    assert open(uefi, "rb").read() == b"ENROLLED"

    run = os.path.join(root, "run")
    os.makedirs(state)
    proc = subprocess.Popen(
        [sys.executable, os.path.abspath(__file__), "--tpu-serve",
         "--ppid", "0", "--state", state, "--socket", tpu_socket(state, run)]
    )
    sock = tpu_socket(state, run)
    deadline = time.time() + 3
    while not os.path.exists(sock):
        if proc.poll() is not None:
            raise SystemExit("tpu server exited")
        if time.time() > deadline:
            raise SystemExit("tpu socket missing")
        time.sleep(0.02)
    try:
        assert _client(sock, "STAT")[0] == "OK %d" % TPU_BYTES
        assert _client(sock, "WRITE 0 2", bytes((2, 255)))[0] == "OK"
        text, _rest = _client(sock, "DOT 0 1 1 16")
        assert text == "OK -2", text
        _text, data = _client(sock, "READ 16 4")
        assert struct.unpack("<i", data)[0] == -2
        assert _client(sock, "NOPE")[0].startswith("ERR")
    finally:
        proc.terminate()
        proc.wait(timeout=3)
    restarted = Tpu(os.path.join(state, "state.bin"))
    assert struct.unpack("<i", restarted.read(16, 4))[0] == -2
    os.close(restarted.fd)
    devices = tpu_devices(sock)
    assert "reconnect-ms=200" in devices[1]
    assert TPU_NAME in devices[-1]
    cleaned = graphics_boot(
        ["-vga", "std", "-device", "virtio-gpu-pci", "-device", "virtio-nvgpu-pci,id=nvkvm0", "-kernel", "vmlinuz"],
        {},
    )
    assert cleaned[0] == "-device" and "nvgpu" in cleaned[1]
    assert "-vga" in cleaned and cleaned[-1] == "none"
    assert "virtio-gpu-pci" not in cleaned
    assert graphics_boot(["-vga", "std"], {"GS_QEMU_VGA": "keep"}) == ["-vga", "std"]
    assert sb_required("", {"GS_SB_ENFORCE": "1"}) is True
    assert sb_required("/vars", {"GS_SB_ENFORCE": "1"}) is False
    assert sb_required("", {}) is False
    print("self-test ok")


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as exc:
        sys.stderr.write("gs-kata-shim: %s\n" % exc)
        sys.exit(1)
