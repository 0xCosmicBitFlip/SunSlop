"""Process config from the gs-config ConfigMap and the cookie secret."""
import os
from dataclasses import dataclass

from gs.model import SUNSHINE_BASE, log

@dataclass
class Config:
    node: str
    namespace: str
    users_file: str
    secret: bytes
    cookie_ttl: int
    idle_seconds: int
    persist_root: str
    common_host: str
    common_mount: str
    image: str
    runtime: str
    gpu_count: int
    sessions_per_gpu: int
    http_port: int
    selkies_port: int
    ready_timeout: int
    device_plugin: bool
    http_foreign: str
    memory_limit: str
    cpu_limit: str
    cert_proxy: bool = True
    proxy_store: str = "/var/lib/gs-proxy/store.json"
    admin_password: str = ""
    sunshine_web_user: str = ""
    sunshine_web_password: str = ""
    common_dir: str = "common"
    layer_dir: str = "gs-layer"
    proxy_dir: str = "proxy"
    layer_host: str = ""
    layer_mount: str = "/gs-layer"
    seat_user: str = "gsuser"
    seat_uid: int = 1000
    seat_gid: int = 1000
    seat_home: str = "/home/gsuser"
    xdg_runtime: str = "/run/user/1000"
    wayland_display: str = "wayland-0"
    sunshine_base: int = SUNSHINE_BASE
    memory_request: str = "8Gi"
    cpu_request: str = "2"
    kata_memory: str = "16384"
    nvidia_caps: str = "compute,utility,graphics,display,video"
    selkies_encoder: str = "nvh264enc"
    persist_mount: str = "/var/lib/gs-persist"
    role: str = "all"
    orch_url: str = ""
    https_offset: int = -5
    web_offset: int = 1
    rtsp_offset: int = 21
    udp_offsets: tuple = (9, 10, 11, 13, 21)
    proxy_label: str = "gs-proxy"
    orch_label: str = "gs-orchestrator"
    seat_label: str = "gamestream"
    advertise: str = ""
    proxy_cert_publish: str = ""
    proxy_cert_host: str = ""
    proxy_cert_mount: str = "/etc/gamestream/proxy-client.crt"
    proxy_client_name: str = "gs-proxy"
    proxy_cert_required: bool = True
    sunshine_bind: str = "0.0.0.0"
    sunshine_address_family: str = "ipv4"
    sunshine_origin: str = "lan"
    sunshine_state_file: str = "sunshine_state.json"
    sunshine_config_rel: str = ".config/sunshine"
    selkies_addr: str = "0.0.0.0"
    public_http_base: str = ""
    kata_firmware: str = "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd"
    kata_firmware_vars: str = "/usr/share/edk2/ovmf/OVMF_VARS.fd"
    kata_secure_boot: bool = True
    tpu_emulation: bool = True
    tpu_state_dir: str = "tpu"
    ovn_back_subnet: str = "ovn-default"
    ovn_front_network: str = "cs1-resident"
    ovn_front_nad_ns: str = "default"


def env_get(name, default):
    val = os.environ.get(name)
    if val is None or val == "":
        return default
    return val


def env_int(name, default):
    return int(env_get(name, str(default)))


def env_csv_ints(name, default):
    raw = env_get(name, default)
    out = []
    for part in str(raw).split(","):
        part = part.strip()
        if part:
            out.append(int(part))
    return tuple(out)


def env_bool(name, default):
    return env_get(name, "true" if default else "false").lower() not in ("0", "false", "no")


def _safe(value, label):
    if not value or any(c in value for c in "\n\r\t;|&$`<>'\"\\"):
        raise SystemExit(f"bad {label}")
    return value


def _dir_name(value, label):
    name = value.strip("/")
    if not name or name in (".", "..") or "/" in name:
        raise SystemExit(f"bad {label}")
    return name


def derive_storage(persist_root, common_dir, layer_dir, proxy_dir, persist_mount,
                   common_host="", layer_host="", proxy_store="", cert_file="proxy-client.crt"):
    """Host homes are <root>/<login>. The three shared dirs sit beside them.
    The proxy file is <persist_mount>/<proxy_dir>/store.json inside the proxy.
    The public cert is the sibling file seats mount read-only.
    """
    root = persist_root.rstrip("/")
    mount = persist_mount.rstrip("/")
    common = common_host or f"{root}/{common_dir}"
    layer = layer_host or f"{root}/{layer_dir}"
    store = proxy_store or f"{mount}/{proxy_dir}/store.json"
    name = (cert_file or "proxy-client.crt").strip("/")
    cert_publish = f"{mount}/{proxy_dir}/{name}"
    cert_host = f"{root}/{proxy_dir}/{name}"
    return common, layer, store, cert_publish, cert_host


def load_config():
    secret_path = env_get("COOKIE_SECRET_FILE", "/etc/gamestream/cookie.secret")
    secret = open(secret_path, "rb").read().strip()
    if len(secret) < 16 or b"CHANGE_ME" in secret:
        raise SystemExit("cookie secret must be at least 16 bytes and must not be the CHANGE_ME placeholder")
    admin_password = os.environ.get("ADMIN_PASSWORD", "")
    if not admin_password.strip() or "CHANGE_ME" in admin_password:
        raise SystemExit(
            "ADMIN_PASSWORD is empty or still the CHANGE_ME placeholder. "
            "An empty password would leave /admin open on the proxy."
        )
    flag = env_get("CERT_PROXY", "true").lower()
    persist_root = env_get("PERSIST_ROOT", "/var/lib/gamestream/persistent")
    common_dir = _dir_name(env_get("COMMON_DIR", "common"), "COMMON_DIR")
    layer_dir = _dir_name(env_get("LAYER_DIR", "gs-layer"), "LAYER_DIR")
    proxy_dir = _dir_name(env_get("PROXY_DIR", "proxy"), "PROXY_DIR")
    persist_mount = _safe(env_get("PERSIST_MOUNT", "/var/lib/gs-persist"), "PERSIST_MOUNT")
    role = env_get("GS_ROLE", "all").strip().lower()
    if role not in ("all", "proxy", "orchestrator"):
        raise SystemExit(f"bad GS_ROLE {role}")
    cert_file = _safe(env_get("PROXY_CLIENT_CERT", "proxy-client.crt"), "PROXY_CLIENT_CERT")
    common_host, layer_host, proxy_store, cert_publish, cert_host = derive_storage(
        persist_root, common_dir, layer_dir, proxy_dir, persist_mount,
        common_host=os.environ.get("COMMON_HOST_PATH", ""),
        layer_host=os.environ.get("LAYER_HOST_PATH", ""),
        proxy_store=os.environ.get("PROXY_STORE", ""),
        cert_file=cert_file,
    )
    seat_user = _safe(env_get("SEAT_USER", "gsuser"), "SEAT_USER")
    seat_uid = env_int("SEAT_UID", 1000)
    seat_gid = env_int("SEAT_GID", 1000)
    seat_home = _safe(env_get("SEAT_HOME", "/home/" + seat_user), "SEAT_HOME")
    kata_secure_boot = env_bool("KATA_SECURE_BOOT", True)
    kata_firmware = ""
    kata_firmware_vars = ""
    if kata_secure_boot:
        kata_firmware = _safe(
            env_get("KATA_FIRMWARE", "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd"),
            "KATA_FIRMWARE",
        )
        kata_firmware_vars = _safe(
            env_get("KATA_FIRMWARE_VARS", "/usr/share/edk2/ovmf/OVMF_VARS.fd"),
            "KATA_FIRMWARE_VARS",
        )
    tpu_emulation = env_bool("TPU_EMULATION", True)
    tpu_state_dir = "tpu"
    if tpu_emulation:
        tpu_state_dir = _dir_name(env_get("TPU_STATE_DIR", "tpu"), "TPU_STATE_DIR")
        if tpu_state_dir == "uefi":
            raise SystemExit("bad TPU_STATE_DIR")
    xdg_runtime = _safe(env_get("XDG_RUNTIME_DIR", f"/run/user/{seat_uid}"), "XDG_RUNTIME_DIR")
    wayland_display = _safe(env_get("WAYLAND_DISPLAY", "wayland-0"), "WAYLAND_DISPLAY")
    common_mount = _safe(
        env_get("COMMON_MOUNT", env_get("COMMON_MOUNT_PATH", "/games")), "COMMON_MOUNT"
    )
    layer_mount = _safe(env_get("LAYER_MOUNT", "/gs-layer"), "LAYER_MOUNT")
    http_port = env_int("HTTP_PORT", 8080)
    orch_url = env_get("ORCH_URL", "")
    if role == "proxy" and not orch_url:
        orch_url = f"http://{env_get('ORCH_NAME', 'gs-orchestrator')}:{http_port}"
    return Config(
        node=os.environ["NODE_NAME"],
        namespace=os.environ.get("POD_NAMESPACE", ""),
        users_file=env_get("USERS_FILE", "/etc/gamestream/users.csv"),
        secret=secret,
        cookie_ttl=env_int("COOKIE_TTL", 30 * 24 * 3600),
        idle_seconds=env_int("IDLE_SECONDS", 600),
        persist_root=persist_root.rstrip("/"),
        common_host=common_host,
        common_mount=common_mount,
        image=env_get("SEAT_IMAGE", "gamestream:local"),
        runtime=env_get("RUNTIME_CLASS", "nvkvm-kata"),
        gpu_count=env_int("GPU_COUNT", 2),
        sessions_per_gpu=env_int("SESSIONS_PER_GPU", 8),
        http_port=http_port,
        selkies_port=env_int("SELKIES_PORT", 8082),
        ready_timeout=env_int("READY_TIMEOUT", 900),
        device_plugin=env_get("DEVICE_PLUGIN", "true").lower() not in ("0", "false", "no"),
        http_foreign=env_get("HTTP_FOREIGN", "redirect"),
        memory_limit=env_get("SEAT_MEMORY_LIMIT", "16Gi"),
        cpu_limit=env_get("SEAT_CPU_LIMIT", "8"),
        cert_proxy=flag not in ("0", "false", "no"),
        proxy_store=proxy_store,
        admin_password=admin_password,
        sunshine_web_user=os.environ.get("SUNSHINE_WEB_USER", ""),
        sunshine_web_password=os.environ.get("SUNSHINE_WEB_PASSWORD", ""),
        common_dir=common_dir,
        layer_dir=layer_dir,
        proxy_dir=proxy_dir,
        layer_host=layer_host,
        layer_mount=layer_mount,
        seat_user=seat_user,
        seat_uid=seat_uid,
        seat_gid=seat_gid,
        seat_home=seat_home,
        xdg_runtime=xdg_runtime,
        wayland_display=wayland_display,
        sunshine_base=env_int("SUNSHINE_BASE", SUNSHINE_BASE),
        memory_request=env_get("SEAT_MEMORY_REQUEST", "8Gi"),
        cpu_request=env_get("SEAT_CPU_REQUEST", "2"),
        kata_memory=env_get("KATA_MEMORY_MIB", "16384"),
        nvidia_caps=env_get(
            "NVIDIA_DRIVER_CAPABILITIES", "compute,utility,graphics,display,video"
        ),
        selkies_encoder=env_get("SELKIES_ENCODER", "nvh264enc"),
        persist_mount=persist_mount,
        role=role,
        orch_url=orch_url,
        https_offset=env_int("SUNSHINE_HTTPS_OFFSET", -5),
        web_offset=env_int("SUNSHINE_WEB_OFFSET", 1),
        rtsp_offset=env_int("SUNSHINE_RTSP_OFFSET", 21),
        udp_offsets=env_csv_ints("SUNSHINE_UDP_OFFSETS", "9,10,11,13,21"),
        proxy_label=env_get("PROXY_NAME", "gs-proxy"),
        orch_label=env_get("ORCH_NAME", "gs-orchestrator"),
        seat_label=env_get("SEAT_APP", "gamestream"),
        advertise=os.environ.get("PROXY_ADVERTISE", ""),
        proxy_cert_publish=cert_publish,
        proxy_cert_host=cert_host,
        proxy_cert_mount=_safe(env_get("PROXY_CERT_MOUNT", "/etc/gamestream/proxy-client.crt"), "PROXY_CERT_MOUNT"),
        proxy_client_name=_safe(env_get("PROXY_CLIENT_NAME", "gs-proxy"), "PROXY_CLIENT_NAME"),
        proxy_cert_required=env_bool("PROXY_CERT_REQUIRED", True),
        sunshine_bind=env_get("SUNSHINE_BIND", "0.0.0.0"),
        sunshine_address_family=env_get("SUNSHINE_ADDRESS_FAMILY", "ipv4"),
        sunshine_origin=env_get("SUNSHINE_ORIGIN_WEB_UI", "lan"),
        sunshine_state_file=env_get("SUNSHINE_STATE_FILE", "sunshine_state.json"),
        sunshine_config_rel=_safe(env_get("SUNSHINE_CONFIG_REL", ".config/sunshine"), "SUNSHINE_CONFIG_REL"),
        selkies_addr=env_get("SELKIES_ADDR", "0.0.0.0"),
        public_http_base=os.environ.get("PUBLIC_HTTP_BASE", ""),
        kata_firmware=kata_firmware,
        kata_firmware_vars=kata_firmware_vars,
        kata_secure_boot=kata_secure_boot,
        tpu_emulation=tpu_emulation,
        tpu_state_dir=tpu_state_dir,
        ovn_back_subnet=_safe(env_get("OVN_BACK_SUBNET", "ovn-default"), "OVN_BACK_SUBNET"),
        ovn_front_network=_safe(env_get("OVN_FRONT_NETWORK", "cs1-resident"), "OVN_FRONT_NETWORK"),
        ovn_front_nad_ns=_safe(env_get("OVN_FRONT_NAD_NS", "default"), "OVN_FRONT_NAD_NS"),
    )


def require_persist_mount(path):
    """The certificate store has to be the shared disk, not a local directory.

    A hostPath that was never mounted shows up as a subdirectory of `/`.
    Starting anyway creates a second certificate that the other node will
    not trust. GS_PERSIST_ALLOW_UNMOUNTED=1 is only for a local run.
    """
    if os.environ.get("GS_PERSIST_ALLOW_UNMOUNTED", "") == "1":
        log(f"persist: {path} mount check skipped")
        return
    real = os.path.realpath(path)
    best = None
    try:
        mounts = open("/proc/mounts")
    except OSError as exc:
        raise SystemExit(f"persist: cannot read mounts: {exc}") from exc
    with mounts:
        for line in mounts:
            parts = line.split()
            if len(parts) < 3:
                continue
            mnt = os.path.realpath(parts[1].replace("\\040", " "))
            if real == mnt or real.startswith(mnt.rstrip("/") + "/"):
                if best is None or len(mnt) > len(best[0]):
                    best = (mnt, parts[0], parts[2])
    if best is None or best[0] != real:
        raise SystemExit(
            f"{path} is not a mount. Refusing to start, because a local directory "
            "would mint a second certificate. The pod must mount the shared "
            "PERSIST_ROOT at this path. GS_PERSIST_ALLOW_UNMOUNTED=1 is only for a local run."
        )
    marker = os.path.join(real, ".sunslop-volume")
    if not os.path.isfile(marker):
        raise SystemExit(
            f"{marker} is missing. On the shared filesystem, run "
            "`touch <PERSIST_ROOT>/.sunslop-volume` once, and confirm every "
            "proxy node and the orchestrator node see that same file. "
            "A node-local directory would mint a second certificate."
        )
    log(f"persist: {path} is {best[1]} ({best[2]})")
