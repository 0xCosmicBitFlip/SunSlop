"""Create, find, and delete seat pods."""
import json
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from gs.kube import activity_unix, pod_gpu, pod_ip, pod_node, pod_phase, pod_ready
from gs.model import (
    ACTIVITY,
    PORT_HI,
    PORT_LO,
    Place,
    advertise_host,
    api_token,
    log,
    pick_gpu,
    pick_node,
    place_from_api,
    public_base,
    still_active,
)

class Seats:
    def __init__(self, cfg, directory, kube):
        self.cfg = cfg
        self.directory = directory
        self.kube = kube
        self._locks = {}
        self._guard = threading.Lock()
        self.activity = {}
        self._patched = {}
        self.starting = set()
        self.board = None

    def _lock(self, name):
        with self._guard:
            lock = self._locks.get(name)
            if lock is None:
                lock = threading.Lock()
                self._locks[name] = lock
            return lock

    def touch(self, name):
        now = time.monotonic()
        self.activity[name] = now
        if now - self._patched.get(name, 0) < 30:
            return
        self._patched[name] = now
        threading.Thread(target=self._announce, args=(name,), daemon=True).start()

    def _announce(self, name):
        user = self.directory.get(name)
        if user is None:
            return
        if self.board is not None:
            try:
                self.board.stamp(name)
            except Exception as exc:
                log(f"{name}: activity stamp {exc}")
        try:
            code, data = self.kube.patch_pod(
                user.pod_name,
                {"metadata": {"annotations": {ACTIVITY: str(int(time.time()))}}},
            )
        except Exception as exc:
            log(f"{name}: activity patch {exc}")
            return
        if code == 404:
            return
        if code not in (200, 201):
            msg = data.get("message", data) if isinstance(data, dict) else data
            log(f"{name}: activity patch {code} {msg}")

    def lookup(self, user, prefer_node=None):
        """Ready seat, or None. Does not create it. kind is local to prefer_node."""
        if user is None:
            return None
        prefer = prefer_node or self.cfg.node
        pod = self.kube.get_pod(user.pod_name)
        if not pod or pod_phase(pod) != "Running" or not pod_ready(pod):
            return None
        ip = pod_ip(pod) or ""
        if not ip:
            return None
        node = pod_node(pod) or ""
        host = self._host_for(node)
        kind = "local" if node == prefer else "remote"
        return Place(kind, ip, host, node)

    def ensure(self, user, prefer_node=None):
        """Place is local only when the seat is on prefer_node (this proxy)."""
        self.touch(user.name)
        prefer = prefer_node or self.cfg.node
        with self._lock(user.name):
            self.starting.add(user.name)
            try:
                if self.board is not None and not self.board.ready:
                    pod = self.kube.get_pod(user.pod_name)
                    # An already-running seat keeps its stream. Do not wait
                    # out ready_timeout, and do not create, until this
                    # process has finished the election.
                    if (
                        pod
                        and pod_phase(pod) == "Running"
                        and pod_ready(pod)
                        and pod_ip(pod)
                    ):
                        return self._from_pod(user, pod, prefer)
                    return Place("inventory", "no seat inventory yet")
                return self._ensure(user, prefer)
            finally:
                self.starting.discard(user.name)

    def _from_pod(self, user, pod, prefer):
        node = pod_node(pod) or ""
        host = self._host_for(node)
        if node and node != prefer:
            ip = pod_ip(pod) if pod_ready(pod) and pod_phase(pod) == "Running" else ""
            return Place("remote", ip or "", host, node)
        ip = self._wait_ready(user, pod)
        if ip:
            return Place("local", ip, host or self._host_for(prefer), node or prefer)
        return Place("error", "existing pod did not become ready", host, node)

    def _ensure(self, user, prefer):
        pod = self.kube.get_pod(user.pod_name)
        if pod and pod_phase(pod) in ("Failed", "Succeeded"):
            log(f"{user.name}: clearing {pod_phase(pod)} pod")
            self.kube.delete_pod(user.pod_name)
            pod = None
            for _ in range(20):
                if self.kube.get_pod(user.pod_name) is None:
                    break
                time.sleep(0.5)
        if pod:
            return self._from_pod(user, pod, prefer)
        node, host = self._choose(prefer)
        if not node:
            if self.cfg.role == "orchestrator" and not self._frontend_nodes():
                return Place("error", "no proxy is ready")
            return Place("full", "")
        gpu = self._pick(node)
        if gpu is None:
            return Place("full", "")
        body = seat_pod(self.cfg, user, gpu, node)
        code, data = self.kube.create_pod(body)
        if code == 409:
            pod = self.kube.get_pod(user.pod_name)
            if pod:
                return self._from_pod(user, pod, prefer)
            return Place("error", "create conflict but pod is gone")
        if code not in (200, 201):
            msg = (data or {}).get("message", data)
            log(f"{user.name}: create {code} {msg}")
            return Place("error", str(msg)[:300])
        if self.board is not None:
            try:
                self.board.own(user.name, node)
            except Exception as exc:
                log(f"{user.name}: owner {exc}")
        log(f"{user.name}: creating on {node} gpu {gpu} "
            f"sunshine {self.cfg.sunshine_base + PORT_LO}-{self.cfg.sunshine_base + PORT_HI}")
        if node != prefer:
            return Place("remote", "", host, node)
        ip = self._wait_ready(user, data)
        if not ip:
            return Place("error", "pod never became ready", host, node)
        return Place("local", ip, host, node)

    def _frontend_nodes(self):
        labels = {self.cfg.proxy_label}
        if self.cfg.role != "orchestrator":
            labels.add(self.cfg.orch_label)
        out = {}
        for pod in self.kube.list_apps(labels):
            if pod_phase(pod) not in ("Pending", "Running"):
                continue
            node = pod_node(pod)
            if not node:
                continue
            app = ((pod.get("metadata") or {}).get("labels") or {}).get("app")
            host = advertise_host(
                pod, self.cfg.ovn_front_network, self.cfg.ovn_front_nad_ns
            )
            if node not in out or app == self.cfg.proxy_label:
                out[node] = host or out.get(node, "")
        return out

    def _host_for(self, node):
        if not node:
            return ""
        nodes = self._frontend_nodes()
        if nodes.get(node):
            return nodes[node]
        if node == self.cfg.node and self.cfg.advertise:
            return self.cfg.advertise
        return ""

    def _choose(self, prefer):
        nodes = self._frontend_nodes()
        if not nodes:
            if self.cfg.role == "orchestrator":
                return None, ""
            return prefer, self.cfg.advertise or ""
        return pick_node(prefer, nodes, lambda node: self._pick(node) is not None)

    def _pick(self, node=None):
        node = node or self.cfg.node
        assigned = []
        for pod in self.kube.list_seats():
            if pod_node(pod) != node:
                continue
            if pod_phase(pod) not in ("Pending", "Running"):
                continue
            gpu = pod_gpu(pod)
            if gpu is not None:
                assigned.append(gpu)
        return pick_gpu(assigned, self.cfg.gpu_count, self.cfg.sessions_per_gpu)

    def _wait_ready(self, user, pod):
        deadline = time.monotonic() + self.cfg.ready_timeout
        name = user.pod_name
        while time.monotonic() < deadline:
            self.touch(user.name)
            if pod and pod_ready(pod) and pod_ip(pod):
                return pod_ip(pod)
            time.sleep(1)
            pod = self.kube.get_pod(name)
            if pod is None:
                return None
            if pod_phase(pod) in ("Failed", "Succeeded"):
                log(f"{user.name}: pod {pod_phase(pod)} while waiting")
                return None
        log(f"{user.name}: not Ready after {self.cfg.ready_timeout}s")
        return None

    def reconcile(self):
        if self.board is None:
            return
        pods = []
        for pod in self.kube.list_seats():
            if pod_phase(pod) not in ("Pending", "Running"):
                continue
            labels = pod.get("metadata", {}).get("labels") or {}
            name = labels.get("gamestream.local/user")
            if not name:
                continue
            pods.append({
                "user": name,
                "node": pod_node(pod) or "",
                "ann": activity_unix(pod),
            })
        self.board.reconcile(pods)

    def reap(self):
        if self.board is not None and not self.board.ready:
            return
        now = time.monotonic()
        now_w = time.time()
        for pod in self.kube.list_seats():
            if pod_phase(pod) not in ("Pending", "Running"):
                continue
            labels = pod.get("metadata", {}).get("labels") or {}
            name = labels.get("gamestream.local/user")
            if not name or name in self.starting:
                continue
            if self.board is not None:
                try:
                    if not self.board.reapable(name, activity_unix(pod), now_w):
                        continue
                except Exception as exc:
                    log(f"reap: {exc}")
                    return
            else:
                ann = activity_unix(pod)
                remote_idle = None if ann is None else now_w - ann
                last = self.activity.get(name)
                if last is None and remote_idle is None:
                    self.activity[name] = now
                    continue
                local_idle = None if last is None else now - last
                if still_active(local_idle, remote_idle, self.cfg.idle_seconds):
                    continue
            log(f"{name}: idle, deleting pod")
            code, data = self.kube.delete_pod(pod["metadata"]["name"])
            if code not in (200, 202, 404):
                log(f"{name}: delete {code} {data}")
            self.activity.pop(name, None)
            if self.board is not None:
                try:
                    self.board.drop(name)
                except Exception as exc:
                    log(f"{name}: drop {exc}")

    def owner_url(self, node):
        host = self._host_for(node)
        if not host:
            return None
        return public_base(self.cfg, host)

    def status(self):
        """Pod list plus the board, for the debug page. No writes."""
        now = time.time()
        seats = []
        for pod in self.kube.list_seats():
            labels = (pod.get("metadata") or {}).get("labels") or {}
            name = labels.get("gamestream.local/user") or ""
            ann = activity_unix(pod)
            seats.append({
                "user": name,
                "phase": pod_phase(pod),
                "ready": bool(pod_ready(pod)),
                "node": pod_node(pod) or "",
                "ip": pod_ip(pod) or "",
                "gpu": pod_gpu(pod),
                "activity": ann,
                "idle": None if ann is None else max(0, int(now - ann)),
            })
        board = {"id": getattr(self.cfg, "instance", ""), "ready": self.board is None}
        if self.board is not None:
            try:
                board = self.board.view()
            except Exception as exc:
                board = {"id": self.board.me, "ready": False, "error": str(exc)[:200],
                         "heartbeats": [], "owners": {}, "activity": {}}
        owners = board.get("owners") or {}
        acts = board.get("activity") or {}
        for seat in seats:
            seat["owner"] = owners.get(seat["user"]) or ""
            cached = acts.get(seat["user"])
            if cached is not None and (seat["activity"] is None or cached > seat["activity"]):
                seat["activity"] = cached
                seat["idle"] = max(0, int(now - cached))
        return {"orchestrator": board, "seats": seats}



def games_volumes(cfg, user):
    """common mounts GAMES_HOST and GAMESSD_HOST read-write. unique mounts neither."""
    mode = getattr(user, "games", "") or "unique"
    if mode != "common":
        return [], [], []
    host = (getattr(cfg, "games_host", "") or "").strip()
    ssd = (getattr(cfg, "gamessd_host", "") or "").strip()
    if not host or not ssd:
        raise ValueError(f"{user.name}: common needs GAMES_HOST and GAMESSD_HOST")
    mount = getattr(cfg, "games_mount", "") or "/games"
    ssd_mount = getattr(cfg, "gamessd_mount", "") or "/gamessd"
    mounts = [
        {"name": "games", "mountPath": mount},
        {"name": "gamessd", "mountPath": ssd_mount},
    ]
    volumes = [
        {"name": "games", "hostPath": {"path": host, "type": "DirectoryOrCreate"}},
        {"name": "gamessd", "hostPath": {"path": ssd, "type": "DirectoryOrCreate"}},
    ]
    env = [
        {"name": "GS_GAMES", "value": mount},
        {"name": "GS_GAMESSD", "value": ssd_mount},
    ]
    return mounts, volumes, env


def probe_failures(ready_timeout, period=2):
    """Kubelet checks for the labwc socket this many times.

    The layer install is an init container, so this probe only covers the
    desktop coming up after that. The orchestrator wait still has to cover
    both, which is why READY_TIMEOUT stays at 900s.
    """
    ready = max(int(ready_timeout), period)
    return max(1, (ready + period - 1) // period)


def user_home(cfg, user):
    """Home host path. disk=hdd uses PERSIST_HDD_ROOT, disk=ssd uses the SSD root."""
    disk = getattr(user, "disk", "")
    if disk == "hdd":
        root = getattr(cfg, "persist_hdd", "") or ""
    elif disk == "ssd":
        root = getattr(cfg, "persist_ssd", "") or cfg.persist_root
    else:
        raise ValueError(f"{user.name}: disk must be hdd or ssd")
    if not root:
        raise ValueError(f"{user.name}: no persist root for {disk}")
    return root.rstrip("/") + "/" + user.name


def kata_annotations(cfg, home, activity):
    """What the host shim reads. kernel_params is appended by Kata, and only
    if configuration-nvkvm.toml lists it in enable_annotations. The firmware
    annotation is the OVMF code image; the per-login variable store is the
    sunslop.uefi_vars token, because Kata 4.1 does not pass firmware_volume
    through on a normal guest.
    """
    ann = {
        "io.katacontainers.config.hypervisor.default_vcpus": cfg.cpu_limit,
        "io.katacontainers.config.hypervisor.default_memory": cfg.kata_memory,
        "io.katacontainers.config.hypervisor.default_maxmemory": cfg.kata_max_memory,
        "io.katacontainers.config.hypervisor.enable_virtio_mem": "true",
        ACTIVITY: activity,
    }
    home = home.rstrip("/")
    params = []
    if cfg.kata_secure_boot:
        ann["io.katacontainers.config.hypervisor.firmware"] = cfg.kata_firmware
        params.append("sunslop.uefi_vars=%s/uefi/OVMF_VARS.fd" % home)
        params.append("sunslop.uefi_code=%s" % cfg.kata_firmware)
    if cfg.tpu_emulation:
        params.append("sunslop.tpu_state=%s/%s" % (home, cfg.tpu_state_dir))
    if params:
        ann["io.katacontainers.config.hypervisor.kernel_params"] = " ".join(params)
    if cfg.ovn_back_subnet:
        ann["ovn.kubernetes.io/logical_switch"] = cfg.ovn_back_subnet
    return ann


def seat_pod(cfg, user, gpu, node=None):
    home = user_home(cfg, user)
    layer = cfg.layer_host or (cfg.persist_root.rstrip("/") + "/" + cfg.layer_dir)
    wayland = cfg.xdg_runtime.rstrip("/") + "/" + cfg.wayland_display
    node = node or cfg.node
    limits = {"memory": cfg.memory_limit, "cpu": cfg.cpu_limit}
    requests = {"memory": cfg.memory_request, "cpu": cfg.cpu_request}
    if cfg.device_plugin:
        limits["nvidia.com/gpu"] = "1"
        requests["nvidia.com/gpu"] = "1"
    base = cfg.sunshine_base
    udp = ",".join(str(base + off) for off in cfg.udp_offsets)
    env = [
        {"name": "SUNSHINE_BASE_PORT", "value": str(base)},
        {"name": "SUNSHINE_HTTPS_PORT", "value": str(base + cfg.https_offset)},
        {"name": "SUNSHINE_WEB_PORT", "value": str(base + cfg.web_offset)},
        {"name": "SUNSHINE_RTSP_PORT", "value": str(base + cfg.rtsp_offset)},
        {"name": "SUNSHINE_UDP_PORTS", "value": udp},
        {"name": "SUNSHINE_HTTPS_OFFSET", "value": str(cfg.https_offset)},
        {"name": "SUNSHINE_WEB_OFFSET", "value": str(cfg.web_offset)},
        {"name": "SUNSHINE_RTSP_OFFSET", "value": str(cfg.rtsp_offset)},
        {"name": "SUNSHINE_UDP_OFFSETS", "value": ",".join(str(off) for off in cfg.udp_offsets)},
        {"name": "SUNSHINE_BIND", "value": cfg.sunshine_bind},
        {"name": "SUNSHINE_ADDRESS_FAMILY", "value": cfg.sunshine_address_family},
        {"name": "SUNSHINE_ORIGIN_WEB_UI", "value": cfg.sunshine_origin},
        {"name": "SUNSHINE_STATE_FILE", "value": cfg.sunshine_state_file},
        {"name": "SUNSHINE_CONFIG_REL", "value": cfg.sunshine_config_rel},
        {"name": "GS_PROXY_CERT", "value": cfg.proxy_cert_mount},
        {"name": "GS_PROXY_CLIENT_NAME", "value": cfg.proxy_client_name},
        {"name": "GS_PROXY_CERT_REQUIRED", "value": "1" if cfg.proxy_cert_required else "0"},
        {"name": "NVIDIA_VISIBLE_DEVICES", "value": str(gpu)},
        {"name": "NVIDIA_DRIVER_CAPABILITIES", "value": cfg.nvidia_caps},
        {"name": "SELKIES_ENCODER", "value": cfg.selkies_encoder},
        {"name": "SELKIES_PORT", "value": str(cfg.selkies_port)},
        {"name": "SELKIES_ADDR", "value": cfg.selkies_addr},
        {"name": "GS_USER", "value": cfg.seat_user},
        {"name": "GS_UID", "value": str(cfg.seat_uid)},
        {"name": "GS_GID", "value": str(cfg.seat_gid)},
        {"name": "GS_HOME", "value": cfg.seat_home},
        {"name": "GS_LAYER", "value": cfg.layer_mount},
        {"name": "XDG_RUNTIME_DIR", "value": cfg.xdg_runtime},
        {"name": "WAYLAND_DISPLAY", "value": cfg.wayland_display},
    ]
    if cfg.tpu_emulation:
        env.append({"name": "GS_TPU_STATE", "value": cfg.seat_home.rstrip("/") + "/" + cfg.tpu_state_dir})
        env.append({"name": "GS_TPU_DEVICE", "value": "/dev/virtio-ports/org.sunslop.tpu"})
    mounts = [
        {"name": "home", "mountPath": cfg.seat_home},
        {"name": "pod-etc", "mountPath": "/etc", "subPath": "etc"},
        {"name": "layer", "mountPath": "/usr", "subPath": "usr", "readOnly": True},
        {"name": "layer", "mountPath": "/opt", "subPath": "opt", "readOnly": True},
    ]
    volumes = [
        {"name": "home", "hostPath": {"path": home, "type": "DirectoryOrCreate"}},
        {"name": "layer", "hostPath": {"path": layer, "type": "DirectoryOrCreate"}},
        {"name": "pod-etc", "emptyDir": {}},
    ]
    game_mounts, game_volumes, game_env = games_volumes(cfg, user)
    mounts[1:1] = game_mounts
    volumes[1:1] = game_volumes
    env.extend(game_env)
    # Memory-backed and private. Not the shared layer, and not another seat's home.
    for name, path, size in (
        ("tmp", "/tmp", "6Gi"),
        ("var-tmp", "/var/tmp", "2Gi"),
        ("var-log", "/var/log", "256Mi"),
        ("var-cache", "/var/cache", "1Gi"),
        ("run", "/run", "1Gi"),
    ):
        mounts.append({"name": name, "mountPath": path})
        volumes.append({"name": name, "emptyDir": {"medium": "Memory", "sizeLimit": size}})
    if cfg.proxy_cert_host:
        mounts.append({
            "name": "proxy-cert",
            "mountPath": cfg.proxy_cert_mount,
            "readOnly": True,
        })
        volumes.append({
            "name": "proxy-cert",
            "hostPath": {"path": cfg.proxy_cert_host, "type": "FileOrCreate"},
        })
    desktop_mounts = list(mounts)
    init_mounts = [
        {"name": "layer", "mountPath": cfg.layer_mount},
        {"name": "pod-etc", "mountPath": "/pod-etc"},
    ]
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": user.pod_name,
            "namespace": cfg.namespace,
            "labels": {
                "app": cfg.seat_label,
                "gamestream.local/user": user.name,
                "gamestream.local/gpu": str(gpu),
            },
            "annotations": kata_annotations(cfg, home, str(int(time.time()))),
        },
        "spec": {
            "restartPolicy": "Never",
            "runtimeClassName": cfg.runtime,
            "nodeName": node,
            "terminationGracePeriodSeconds": 15,
            "initContainers": [
                {
                    "name": "layer",
                    "image": cfg.image,
                    "imagePullPolicy": "IfNotPresent",
                    "command": ["/usr/local/bin/layer-init"],
                    "env": env,
                    "securityContext": {
                        "runAsUser": 0,
                        "capabilities": {
                            "add": ["SYS_ADMIN"],
                            "drop": ["SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "NET_ADMIN"],
                        },
                    },
                    "volumeMounts": init_mounts,
                }
            ],
            "containers": [
                {
                    "name": "desktop",
                    "image": cfg.image,
                    "imagePullPolicy": "IfNotPresent",
                    "env": env,
                    "securityContext": {
                        "runAsUser": 0,
                        "readOnlyRootFilesystem": True,
                        "allowPrivilegeEscalation": False,
                        "capabilities": {
                            # SYS_NICE / IPC_LOCK / SYS_RESOURCE raise rlimits the
                            # desktop user inherits. They are not given to the game.
                            # SYS_ADMIN is absent so root cannot remount the layer rw.
                            "add": ["SYS_NICE", "IPC_LOCK", "SYS_RESOURCE"],
                            "drop": [
                                "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO",
                                "NET_ADMIN", "SYS_BOOT", "BPF",
                            ],
                        },
                    },
                    "readinessProbe": {
                        "exec": {"command": ["/bin/bash", "-lc", f"test -S {wayland}"]},
                        "initialDelaySeconds": 3,
                        "periodSeconds": 2,
                        "failureThreshold": probe_failures(cfg.ready_timeout),
                    },
                    "resources": {"requests": requests, "limits": limits},
                    "volumeMounts": desktop_mounts,
                }
            ],
            "volumes": volumes,
        },
    }


class Inventory(Exception):
    pass


class RemoteSeats:
    """Proxy-side view. The orchestrator owns create, delete, and placement."""

    def __init__(self, cfg):
        self.cfg = cfg
        self._patched = {}
        self._guard = threading.Lock()
        self._rr = 0

    def touch(self, name):
        now = time.monotonic()
        with self._guard:
            if now - self._patched.get(name, 0) < 30:
                return
            self._patched[name] = now
        threading.Thread(target=self._touch, args=(name,), daemon=True).start()

    def _touch(self, name):
        try:
            self._call("POST", "/v1/touch", {"user": name})
        except Exception as exc:
            log(f"{name}: touch {exc}")
            with self._guard:
                self._patched.pop(name, None)

    def lookup(self, user):
        if user is None:
            return None
        try:
            data = self._call("POST", "/v1/lookup", {"user": user.name, "preferNode": self.cfg.node})
        except Exception as exc:
            log(f"{user.name}: lookup {exc}")
            return None
        if not data or data.get("kind") in (None, "down", "missing"):
            return None
        return place_from_api(data)

    def ensure(self, user):
        try:
            data = self._call(
                "POST",
                "/v1/ensure",
                {"user": user.name, "preferNode": self.cfg.node},
                timeout=self.cfg.ready_timeout + 60,
            )
        except Inventory:
            found = self.lookup(user)
            if found is not None:
                return found
            return Place("inventory", "no seat inventory yet")
        except (OSError, urllib.error.URLError) as exc:
            found = self.lookup(user)
            if found is not None:
                return found
            log(f"{user.name}: ensure {exc}")
            return Place("inventory", "orchestrator unavailable")
        return place_from_api(data)

    def owner_url(self, node):
        try:
            data = self._call("POST", "/v1/owner", {"node": node})
        except Exception:
            return None
        return data.get("url") or None

    def status(self):
        try:
            data = self._call("POST", "/v1/status", {})
        except Exception as exc:
            return {"error": str(exc)[:200], "seats": [], "orchestrator": {}}
        return data or {"seats": [], "orchestrator": {}}

    def _call(self, method, path, body, timeout=30):
        addrs = self._addrs()
        payload = json.dumps(body).encode()
        token = "Bearer " + api_token(self.cfg.secret)
        inventory = False
        last = None
        for addr in addrs:
            host = f"[{addr}]" if ":" in addr else addr
            url = f"{self._scheme}://{host}:{self._port}{path}"
            req = urllib.request.Request(url, data=payload, method=method)
            req.add_header("Authorization", token)
            req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    raw = resp.read()
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as exc:
                raw = exc.read()
                if exc.code == 503:
                    inventory = True
                    continue
                raise RuntimeError(f"{exc.code} {raw[:200]!r}") from exc
            except (OSError, urllib.error.URLError) as exc:
                last = exc
                continue
        if inventory:
            raise Inventory()
        raise RuntimeError(f"no orchestrator ({last})")

    def _addrs(self):
        parts = urllib.parse.urlsplit(self.cfg.orch_url)
        host = parts.hostname
        if not host:
            raise RuntimeError("no orchestrator address")
        self._scheme = parts.scheme or "http"
        self._port = parts.port or (443 if self._scheme == "https" else 80)
        infos = socket.getaddrinfo(host, self._port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        seen = []
        for info in infos:
            ip = info[4][0]
            if ip not in seen:
                seen.append(ip)
        if not seen:
            raise RuntimeError("no orchestrator address")
        start = self._rr % len(seen)
        self._rr += 1
        return seen[start:] + seen[:start]

