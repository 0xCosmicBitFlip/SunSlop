"""orchestrator.py --self-test. Not imported at runtime."""
import json
import os
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import gs.api as api
import gs.browser as browser
import gs.config as config
import gs.kube as kube
import gs.model as model
import gs.net as net
import gs.seats as seats


def _bind():
    g = globals()
    for mod in (model, config, kube, seats, net, browser, api):
        for name, value in vars(mod).items():
            if not name.startswith("__"):
                g.setdefault(name, value)


_bind()

def self_test():
    users = load_users(
        "# c\ngsuser0,secret,47989\ngsuser1,other,48089\n"
    )
    assert set(users) == {"gsuser0", "gsuser1"}
    assert list(port_span(47989))[0] == 47984
    assert list(port_span(47989))[-1] == 48010
    assert len(list(port_span(47989))) == SPAN
    try:
        load_users("gsuser0,a,47989\ngsuser1,b,48000\n")
        raise SystemExit("overlap accepted")
    except ValueError:
        pass
    try:
        load_users("common,a,47989\n")
        raise SystemExit("common accepted")
    except ValueError:
        pass
    try:
        load_users("proxy,a,47989\n")
        raise SystemExit("proxy accepted")
    except ValueError:
        pass
    try:
        load_users("gs-layer,a,47989\n")
        raise SystemExit("gs-layer accepted")
    except ValueError:
        pass
    try:
        load_users("library,a,47989\n", reserved_names("library"))
        raise SystemExit("configured dir accepted as a login")
    except ValueError:
        pass
    try:
        load_users("gsuser0,CHANGE_ME_selkies_password,47989\n")
        raise SystemExit("placeholder password accepted")
    except ValueError:
        pass
    assert probe_failures(900) == 450
    assert probe_failures(901) == 451
    secret = b"0123456789abcdef"
    tok = issue_token("gsuser0", secret, 100, now=1_000)
    assert read_token(tok, secret, now=1_050) == "gsuser0"
    assert read_token(tok, secret, now=1_200) is None
    assert read_token(tok, b"0123456789abcdee", now=1_050) is None
    assert pick_gpu([0, 0, 1], 2, 8) == 1
    assert pick_gpu([], 2, 8) == 0
    assert pick_gpu([0] * 8 + [1] * 8, 2, 8) is None
    assert pick_gpu([0] * 8, 2, 8) == 1
    assert still_active(10, 1000, 600)
    assert still_active(1000, 10, 600)
    assert not still_active(1000, 1000, 600)
    assert not still_active(1000, None, 600)
    assert still_active(None, None, 600)
    cfg = Config(
        node="n1", namespace="ns", users_file="", secret=secret, cookie_ttl=10,
        idle_seconds=600, persist_root="/data/persist",
        common_host="/data/persist/common",
        common_mount="/games", image="gamestream:local", runtime="nvkvm-kata",
        gpu_count=2, sessions_per_gpu=8, http_port=8080, selkies_port=8082,
        ready_timeout=180, device_plugin=True, http_foreign="proxy",
        memory_limit="16Gi", cpu_limit="8",
    )
    assert cfg.cert_proxy is True
    common, layer, store, cert_pub, cert_host = derive_storage(
        "/data/persist", "common", "gs-layer", "proxy", "/var/lib/gs-persist"
    )
    assert common == "/data/persist/common"
    assert layer == "/data/persist/gs-layer"
    assert store == "/var/lib/gs-persist/proxy/store.json"
    assert cert_pub == "/var/lib/gs-persist/proxy/proxy-client.crt"
    assert cert_host == "/data/persist/proxy/proxy-client.crt"
    assert "cs1-resident" not in derive_storage(
        "/var/lib/gamestream/persistent", "common", "gs-layer", "proxy", "/var/lib/gs-persist"
    )[0]
    pod = seat_pod(cfg, users["gsuser0"], 1)
    assert pod["spec"]["volumes"][0]["hostPath"]["path"].endswith("/gsuser0")
    assert pod["spec"]["volumes"][1]["hostPath"]["path"].endswith("/common")
    assert pod["spec"]["nodeName"] == "n1"
    assert pod["metadata"]["labels"]["gamestream.local/gpu"] == "1"
    assert pod["metadata"]["annotations"][ACTIVITY].isdigit()
    ann = pod["metadata"]["annotations"]
    assert ann["io.katacontainers.config.hypervisor.firmware"].endswith("OVMF_CODE.secboot.fd")
    boot = ann["io.katacontainers.config.hypervisor.kernel_params"]
    assert "sunslop.tpu_state=/data/persist/gsuser0/tpu" in boot
    assert "sunslop.uefi_vars=/data/persist/gsuser0/uefi/OVMF_VARS.fd" in boot
    assert ".." not in boot
    cfg.tpu_emulation = False
    cfg.kata_secure_boot = False
    quiet = seat_pod(cfg, users["gsuser0"], 1)
    qann = quiet["metadata"]["annotations"]
    assert "io.katacontainers.config.hypervisor.firmware" not in qann
    assert "io.katacontainers.config.hypervisor.kernel_params" not in qann
    qenv = {item["name"]: item["value"] for item in quiet["spec"]["containers"][0]["env"]}
    assert "GS_TPU_STATE" not in qenv
    cfg.tpu_emulation = True
    cfg.kata_secure_boot = True
    assert pod_port(48089, 48089) == 47989
    assert pod_port(48084, 48089) == 47984
    assert pod_port(48098, 48089) == 47998
    assert pod_port(48110, 48089) == 48010
    pod = seat_pod(cfg, users["gsuser1"], 1)
    assert pod["spec"]["containers"][0]["env"][0]["value"] == "47989"
    env = {item["name"]: item["value"] for item in pod["spec"]["containers"][0]["env"]}
    assert env["GS_LAYER"] == "/gs-layer"
    assert env["GS_HOME"] == "/home/gsuser"
    assert env["GS_USER"] == "gsuser"
    assert env["GS_TPU_STATE"] == "/home/gsuser/tpu"
    assert env["GS_TPU_DEVICE"] == "/dev/virtio-ports/org.sunslop.tpu"
    assert pod["spec"]["volumes"][2]["hostPath"]["path"].endswith("/gs-layer")
    desktop = pod["spec"]["containers"][0]
    sec = desktop["securityContext"]
    assert sec["readOnlyRootFilesystem"] is True
    assert "SYS_ADMIN" not in sec["capabilities"]["add"]
    assert "SYS_NICE" in sec["capabilities"]["add"]
    assert "IPC_LOCK" in sec["capabilities"]["add"]
    assert "SYS_RESOURCE" in sec["capabilities"]["add"]
    assert "SYS_ADMIN" in sec["capabilities"]["drop"]
    init = pod["spec"]["initContainers"][0]
    assert init["command"] == ["/usr/local/bin/layer-init"]
    assert "SYS_ADMIN" in init["securityContext"]["capabilities"]["add"]
    mounts = {item["mountPath"]: item for item in desktop["volumeMounts"]}
    assert mounts["/usr"]["readOnly"] is True and mounts["/usr"]["subPath"] == "usr"
    assert mounts["/opt"]["readOnly"] is True
    assert mounts["/games"]["readOnly"] is True
    assert mounts["/etc"]["subPath"] == "etc"
    assert "/gs-layer" not in mounts
    names = [item["name"] for item in desktop["volumeMounts"]]
    assert "layer" not in [item["name"] for item in init["volumeMounts"] if item["mountPath"] == "/usr"]
    assert init["volumeMounts"][0]["mountPath"] == "/gs-layer"
    assert "tmp" in names and "run" in names
    probe = desktop["readinessProbe"]["exec"]["command"][-1]
    assert probe == "test -S /run/user/1000/wayland-0"
    custom = Config(
        node="n1", namespace="ns", users_file="", secret=secret, cookie_ttl=10,
        idle_seconds=600, persist_root="/data/persist",
        common_host="/data/persist/library",
        common_mount="/library", image="seat:custom", runtime="kata-custom",
        gpu_count=2, sessions_per_gpu=8, http_port=8080, selkies_port=9090,
        ready_timeout=180, device_plugin=True, http_foreign="proxy",
        memory_limit="16Gi", cpu_limit="8",
        layer_dir="packages", layer_host="/data/persist/packages", layer_mount="/packages",
        seat_user="player", seat_uid=2000, seat_gid=2000, seat_home="/home/player",
        xdg_runtime="/run/user/2000", wayland_display="wayland-1", sunshine_base=48000,
        memory_request="4Gi", cpu_request="1", kata_memory="8192",
    )
    pod = seat_pod(custom, users["gsuser0"], 0)
    env = {item["name"]: item["value"] for item in pod["spec"]["containers"][0]["env"]}
    assert env["SUNSHINE_BASE_PORT"] == "48000"
    assert env["GS_USER"] == "player"
    assert env["GS_UID"] == "2000"
    assert env["GS_HOME"] == "/home/player"
    assert env["GS_LAYER"] == "/packages"
    assert env["SELKIES_PORT"] == "9090"
    assert pod["spec"]["volumes"][2]["hostPath"]["path"] == "/data/persist/packages"
    assert pod["spec"]["containers"][0]["volumeMounts"][0]["mountPath"] == "/home/player"
    assert pod["spec"]["containers"][0]["readinessProbe"]["exec"]["command"][-1] == "test -S /run/user/2000/wayland-1"
    assert pod["metadata"]["annotations"]["io.katacontainers.config.hypervisor.default_memory"] == "8192"
    assert pod["spec"]["containers"][0]["resources"]["requests"]["memory"] == "4Gi"
    assert public_base(cfg, "10.1.1.9") == "http://10.1.1.9:8080"
    nodes = {"b": "2.2.2.2", "a": "1.1.1.1"}
    assert pick_node("a", nodes, lambda n: True) == ("a", "1.1.1.1")
    assert pick_node("a", nodes, lambda n: n != "a") == ("b", "2.2.2.2")
    assert pick_node("a", nodes, lambda n: False) == (None, "")
    kind, info = Place("local", "10.0.0.5", "1.2.3.4", "n1")
    assert kind == "local" and info == "10.0.0.5"
    assert "host" not in HOP
    _component_test()
    print("self-test ok")


def _component_test():
    """Proxy API, placement, Selkies login, and the foreign-seat redirect."""
    import tempfile
    users_file = os.path.join(tempfile.mkdtemp(), "users.csv")
    open(users_file, "w").write("gsuser0,secret,47989\ngsuser1,other,48089\n")
    directory = Directory(users_file, reserved_names("common", "gs-layer", "proxy"))
    secret = b"0123456789abcdef"

    def front(node, ip):
        return {
            "metadata": {"name": "proxy-" + node, "labels": {"app": "gs-proxy"}, "annotations": {}},
            "spec": {"nodeName": node},
            "status": {"phase": "Running", "hostIP": ip},
        }

    class Kube:
        def __init__(self):
            self.pods = {}
            self.fronts = [front("node-a", "4.4.4.3"), front("node-b", "4.4.4.4")]

        def get_pod(self, name):
            return self.pods.get(name)

        def create_pod(self, body):
            pod = json.loads(json.dumps(body))
            pod["status"] = {
                "phase": "Running",
                "podIP": "10.8.0." + str(8 + len(self.pods)),
                "hostIP": "10.0.0.1",
                "conditions": [{"type": "Ready", "status": "True"}],
            }
            self.pods[pod["metadata"]["name"]] = pod
            return 201, pod

        def delete_pod(self, name):
            self.pods.pop(name, None)
            return 200, {}

        def patch_pod(self, name, body):
            pod = self.pods.get(name)
            if pod is None:
                return 404, {}
            ann = ((body.get("metadata") or {}).get("annotations") or {})
            pod.setdefault("metadata", {}).setdefault("annotations", {}).update(ann)
            return 200, pod

        def list_seats(self):
            return list(self.pods.values())

        def list_apps(self, _names):
            return self.fronts

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    api_port = probe.getsockname()[1]
    probe.close()
    cfg = Config(
        node="orch", namespace="gamestream", users_file=users_file, secret=secret,
        cookie_ttl=100, idle_seconds=600, persist_root="/data/persist",
        common_host="/data/persist/common", common_mount="/games",
        image="gamestream:local", runtime="nvkvm-kata", gpu_count=2,
        sessions_per_gpu=8, http_port=api_port, selkies_port=8082,
        ready_timeout=5, device_plugin=True, http_foreign="redirect",
        memory_limit="16Gi", cpu_limit="8", role="orchestrator",
        proxy_label="gs-proxy", orch_label="gs-orchestrator",
    )
    kube = Kube()
    for i in range(8):
        for gpu in (0, 1):
            name = f"busy-{gpu}-{i}"
            kube.pods[name] = {
                "metadata": {
                    "name": name,
                    "labels": {
                        "gamestream.local/user": name,
                        "gamestream.local/gpu": str(gpu),
                    },
                    "annotations": {},
                },
                "spec": {"nodeName": "node-a"},
                "status": {"phase": "Running", "podIP": "10.1.0.1"},
            }
    seats = Seats(cfg, directory, kube)
    threading.Thread(target=OrchestratorApi(cfg, directory, seats)._http, daemon=True).start()
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", api_port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    else:
        raise SystemExit("orchestrator api did not listen")
    bad = urllib.request.Request(
        f"http://127.0.0.1:{api_port}/v1/ensure", data=b"{}", method="POST",
    )
    bad.add_header("Authorization", "Bearer nope")
    bad.add_header("Content-Type", "application/json")
    try:
        urllib.request.urlopen(bad, timeout=3)
        raise SystemExit("api accepted a bad token")
    except urllib.error.HTTPError as exc:
        assert exc.code == 401
    proxy_cfg = Config(
        node="node-a", namespace="gamestream", users_file=users_file, secret=secret,
        cookie_ttl=100, idle_seconds=600, persist_root="/data/persist",
        common_host="/data/persist/common", common_mount="/games",
        image="gamestream:local", runtime="nvkvm-kata", gpu_count=2,
        sessions_per_gpu=8, http_port=api_port, selkies_port=8082,
        ready_timeout=5, device_plugin=True, http_foreign="redirect",
        memory_limit="16Gi", cpu_limit="8", role="proxy",
        orch_url=f"http://127.0.0.1:{api_port}",
        proxy_label="gs-proxy", public_http_base="https://{host}",
    )
    remote = RemoteSeats(proxy_cfg)
    spilled = remote.ensure(directory.get("gsuser1"))
    assert spilled.kind == "remote", spilled.kind
    assert spilled.proxy_host == "4.4.4.4"
    assert spilled.node == "node-b"
    assert spilled.info == ""
    for pod in list(kube.pods):
        if pod.startswith("busy-"):
            kube.pods.pop(pod)
    # node-a is the proxy asking, and it has room now. A new login lands there.
    home = remote.ensure(directory.get("gsuser0"))
    assert home.kind == "local", home.kind
    assert home.node == "node-a"
    assert home.info.startswith("10.8.0.")
    time.sleep(0.4)
    seats.activity["gsuser0"] = time.monotonic() - 5000
    kube.pods["gs-gsuser0"]["metadata"]["annotations"][ACTIVITY] = str(int(time.time()) - 5000)
    seats.reap()
    assert "gs-gsuser0" not in kube.pods

    echo_box = {}

    def echo():
        listen = socket.socket()
        listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen.bind(("127.0.0.1", 0))
        listen.listen(4)
        echo_box["port"] = listen.getsockname()[1]
        echo_box["ready"].set()
        while True:
            conn, _addr = listen.accept()
            data = b""
            conn.settimeout(3)
            try:
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                conn.close()
                continue
            echo_box["req"] = data
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            conn.close()

    echo_box["ready"] = threading.Event()
    threading.Thread(target=echo, daemon=True).start()
    assert echo_box["ready"].wait(3)
    web = socket.socket()
    web.bind(("127.0.0.1", 0))
    web_port = web.getsockname()[1]
    web.close()

    class WebSeats:
        def __init__(self):
            self.place = Place("local", "127.0.0.1", "4.4.4.4", "node-a")

        def ensure(self, user):
            return self.place

        def touch(self, name):
            return None

        def lookup(self, user):
            return self.place

    web_cfg = Config(
        node="node-a", namespace="gamestream", users_file=users_file, secret=secret,
        cookie_ttl=100, idle_seconds=600, persist_root="/data/persist",
        common_host="/data/persist/common", common_mount="/games",
        image="gamestream:local", runtime="nvkvm-kata", gpu_count=2,
        sessions_per_gpu=8, http_port=web_port, selkies_port=echo_box["port"],
        ready_timeout=5, device_plugin=False, http_foreign="redirect",
        memory_limit="16Gi", cpu_limit="8", cert_proxy=False,
        public_http_base="https://{host}",
    )
    web_seats = WebSeats()
    threading.Thread(target=App(web_cfg, directory, web_seats)._http, daemon=True).start()
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", web_port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    else:
        raise SystemExit("selkies http did not listen")

    def raw_http(port, payload):
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        sock.settimeout(5)
        sock.sendall(payload)
        head, rest = _read_http_head(sock)
        length = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":", 1)[1].strip())
        while len(rest) < length:
            chunk = sock.recv(4096)
            if not chunk:
                break
            rest += chunk
        sock.close()
        return head + b"\r\n\r\n" + rest[:length]

    login = raw_http(
        web_port,
        b"POST /login HTTP/1.1\r\nHost: gs.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 32\r\nConnection: close\r\n\r\n"
        b"username=gsuser0&password=secret",
    )
    assert b" 302 " in login.split(b"\r\n", 1)[0]
    cookie = b""
    for line in login.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:"):
            cookie = line.split(b":", 1)[1].strip().split(b";", 1)[0]
    assert cookie.startswith(b"gs_session=")
    page = raw_http(
        web_port,
        b"GET /play HTTP/1.1\r\nHost: gs.example\r\nCookie: " + cookie + b"\r\nConnection: close\r\n\r\n",
    )
    assert b"Host: gs.example" in echo_box["req"]
    assert b"200" in page.split(b"\r\n", 1)[0]
    web_seats.place = Place("remote", "", "4.4.4.4", "node-b")
    moved = raw_http(
        web_port,
        b"GET /play HTTP/1.1\r\nHost: gs.example\r\nCookie: " + cookie + b"\r\nConnection: close\r\n\r\n",
    )
    status = moved.split(b"\r\n", 1)[0]
    assert b" 307 " in status, status
    assert b"Location: https://4.4.4.4/play" in moved

