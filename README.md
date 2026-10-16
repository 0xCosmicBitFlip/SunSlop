# SunSlop

On-demand [Sunshine](https://github.com/LizardByte/Sunshine) and [Selkies](https://github.com/selkies-project/selkies) seats for Kubernetes. Nothing runs until a client connects. A proxy on each GPU node accepts the connection and asks one orchestrator to create the seat, preferably on that same node. Idle seats are deleted. Home directories and a shared package layer stay on disk.

Moonlight pairs with the proxy, not with a pod. The browser reaches Selkies through the same proxy. One shared certificate, generated on first start, is what every seat trusts.

The install order is [docs/deploy.md](docs/deploy.md): shared disk, passwords, nvkvm-kata, the gate, the label, then `kubectl apply`. [docs/nvkvm-kata.md](docs/nvkvm-kata.md) is the runtime detail behind steps 4 through 6 of that guide. `python3 deploy/render.py` refuses to print manifests while a secret or a Selkies password still contains `CHANGE_ME`.

Kubernetes object names stay `gs-orchestrator`, `gs-proxy`, and `gamestream` unless you change them in [deploy/gs-config.yaml](deploy/gs-config.yaml).

## What you need

- Kubernetes workers that have already passed [docs/nvkvm-kata.md](docs/nvkvm-kata.md). Do not apply a seat until that gate prints `GATE_OK` and the node is labeled `nvkvm.kata/ready=true`. The proxy DaemonSet requires that label as well as `nvidia.com/gpu.present=true`. Seats are pinned with `nodeName`, which does not re-check the RuntimeClass selector, so an unlabeled node must not be running a proxy.
- A filesystem mounted at the same `PERSIST_ROOT` on every proxy node and on the orchestrator node.
- The seat image imported on every GPU node, and one control-plane image (`ORCH_IMAGE`) on every orchestrator node and every proxy node. Redis is a separate image (`REDIS_IMAGE`, `redis:7.4-alpine`). The orchestrator and the proxy use the control-plane image. `GS_ROLE` on the pod is what the entrypoint runs: `orchestrator` starts `orchestrator.py`, `proxy` compiles `gs-relay` and starts `moonlight_proxy.py`.
- Traefik, or anything else that can route HTTP to Service `gs-proxy` on the back network. Moonlight does not go through that HTTP route. It dials the Sunshine ports on the proxy's `cs1-resident` address.

## What listens where

Proxies are a DaemonSet, one per GPU node, with two kube-ovn interfaces. The primary NIC is `OVN_BACK_SUBNET` (the subnet the `default` namespace uses, `ovn-default` unless that namespace was moved). The orchestrator and every seat use only that network, and that is how the proxy reaches Service `gs-orchestrator` and the seat pod IPs. The second NIC is the attachment `OVN_FRONT_NAD_NS/OVN_FRONT_NETWORK` (`default/cs1-resident`). Moonlight dials the address kube-ovn assigns there. The default route stays on the back NIC. There is no `hostNetwork` and no `hostPort`.

The proxy selects `nvidia.com/gpu.present=true` and `nvkvm.kata/ready=true`, and does not request `nvidia.com/gpu`, so it does not consume a seat. Orchestrators are a StatefulSet on the back network, one pod or several (`ORCH_REPLICAS`). They are the only kube API clients. Seat owners and liveliness live in Redis (`gs-redis`) on that same network. Each seat runs Sunshine on `SUNSHINE_BASE` (47989) and Selkies on `SELKIES_PORT` (8082). Clients never pair with a pod.

| Client | Where it connects | What happens |
|---|---|---|
| Moonlight | Any proxy's `cs1-resident` address, `SUNSHINE_BASE` and `SUNSHINE_BASE` + `SUNSHINE_HTTPS_OFFSET` | Pairing and unpaired `serverinfo` stay on the proxy. TLS is terminated, the client certificate selects the login, and a second TLS session to the seat presents the shared proxy certificate. A seat on another node is not spliced. |
| Browser | Traefik to Service `gs-proxy` port `HTTP_PORT` (8080), on the back network | Password form at `/`, then a reverse proxy to that user's Selkies, only when the seat is on this proxy's node. `/pair` is the same login and is where a Moonlight PIN is entered. |
| Admin | `/admin` on that same port | Read-only debug. Reload to refresh. Orchestrator heartbeats, seat idle time, and which clients are paired. It does not pair a client. |

## Configure

[deploy/gs-config.yaml](deploy/gs-config.yaml) is the deploy. Paths, namespace, images, the seat's unix account, ports, and sizes are keys there. Do not search the scripts for a host path or a username.

Two values in that file are site paths, not secrets, and the committed defaults are only a starting point:

| Key | Committed default | Replace with |
|---|---|---|
| `NAMESPACE` | `gamestream` | Your namespace. |
| `PERSIST_ROOT` | `/var/lib/gamestream/persistent` | The shared host directory. The same string on every node. |

Logins and the Selkies passwords live in `users.csv` inside [deploy/orchestrator.yaml](deploy/orchestrator.yaml). The cookie HMAC key and the admin password live in the `gs-cookie` Secret in that same file. The committed values are placeholders. Replace them before `kubectl apply`. An empty `admin.password` leaves the debug page open on the proxy.

```
username,password,sunshine_base_port
gsuser0,CHANGE_ME_selkies_password,47989
gsuser1,CHANGE_ME_selkies_password,48089
```

```yaml
stringData:
  cookie.secret: "CHANGE_ME_cookie_hmac_secret_at_least_32_random_bytes"
  admin.password: "CHANGE_ME_admin_ui_password"
```

`cookie.secret` must be at least 16 bytes. It is the HMAC key for the Selkies cookie and for the proxy-to-orchestrator API. `admin.password` only gates `/admin`. The admin cookie is an HMAC, not the password. `/admin` does not pair clients.

The password column is the Selkies login. `Directory.authenticate` checks it. With `CERT_PROXY=true` (the default) Moonlight ignores the third column and always dials `SUNSHINE_BASE`. The column remains so `CERT_PROXY=false` can fall back to one external port span per user: base−5 through base+21, shifted onto the pod's Sunshine ports. Ranges must not overlap, and `USER_PORT_STRIDE` must be at least 27.

`SamlAuthenticator.consume` is the only function a Keycloak ACS has to grow into. It returns a username that must already be in the file, and the existing cookie issuer does the rest. `/saml/acs` answers 501 until then.

`render.py` copies the ConfigMap into the namespace, the hostPaths, the Service ports, and the example `USER_BASE_n` rows. Kubernetes cannot do that by itself. Re-run it after any change. Do not `kubectl edit` the live ConfigMap and leave a volume on the old path.

## Pairing

Moonlight pairs with the proxy, once, from `/pair`. Sign in with the same password as the desktop. Start pairing in Moonlight and type the four digits that client is showing. The certificate on that handshake is stored for the login in the cookie, not for a user picked from a list. Two people can do this at the same time: each PIN is applied only to the client that is waiting for it. A wrong PIN, or a PIN for a client someone else already claimed, does not move the certificate. Removing a client is on that same page and only removes one that is already on this login. The store is `<PERSIST_ROOT>/<PROXY_DIR>/store.json`, mounted at `<PERSIST_MOUNT>/<PROXY_DIR>/store.json`, so any proxy can finish a pairing another proxy started.

There is one proxy keypair, not one per user. The first proxy or orchestrator to start generates it and leaves it in that store. The public PEM is written beside it as `PROXY_CLIENT_CERT` (`proxy-client.crt`, mode 0644). Every seat mounts that file read-only at `PROXY_CERT_MOUNT`. `seat-boot.py` installs it into `sunshine_state.json` under `PROXY_CLIENT_NAME` on every boot, replacing the previous cert of that name and keeping the device uuid. Do not pair a pod by hand, and do not mint a per-user pod certificate. `/admin` reports whether each login's state file contains the shared cert.

## Sunshine ports

Sunshine itself only stores `port` (`SUNSHINE_BASE`). The rest of the family is that base plus the offsets in `gs-config`. The proxy listens on the same numbers. `seat-boot.py` rewrites the seat's `sunshine.conf` from those values on every boot. Do not change the offsets unless the Sunshine build in the seat image uses the same ones.

Defaults when `SUNSHINE_BASE` is 47989:

| Offset key | Offset | Port | Use |
|---|---|---|---|
| `SUNSHINE_HTTPS_OFFSET` | -5 | TCP 47984 | HTTPS. Terminated on the proxy. Client cert selects the user. |
| (the `port` key) | 0 | TCP 47989 | HTTP. Pairing phases and unpaired `serverinfo`. |
| `SUNSHINE_WEB_OFFSET` | +1 | TCP 47990 | Sunshine web UI, on the pod only. The proxy does not publish it. |
| `SUNSHINE_UDP_OFFSETS` | +9 +10 +11 +13 | UDP 47998, 47999, 48000, 48002 | video, control, audio, and the extra stream port |
| `SUNSHINE_RTSP_OFFSET` | +21 | TCP 48010 and UDP 48010 | RTSP |

After TLS has identified the client, the source address is stuck to that pod, and only if the pod is on this node. Python sends `map <client-ip> <pod-ip> <user>` to `gs-relay` over a Unix socket and waits until that row is installed. The relay binds the UDP ports and the RTSP TCP port, forwards datagrams, and splices RTSP. Replies from the pod go back to the client that last used that port. A `touch` comes back when bytes move, at most every few seconds, and the proxy still patches activity at most every 30 seconds. This is independent of the TLS socket. Two clients behind one NAT share a source address, so UDP follows whichever of them last completed TLS.

`serverinfo` is answered by the proxy when the seat is down, so a Moonlight poll does not boot a GPU. `applist`, `launch`, and the other HTTPS calls wait until the pod is Ready (labwc's socket), holding the already-finished handshake, but only when the seat is local. Moonlight's own HTTP read timeout is only a few seconds, so a remote placement returns immediately and the first click on the owning proxy starts the seat. The pod stays up across the retry. Budget is `READY_TIMEOUT` (900s, long enough for the first layer copy) and it applies only to a local ensure.

## A connection on the wrong proxy

Proxies have the addresses clients can reach. The orchestrator may place the seat on a different GPU node. `HTTP_FOREIGN` is the same switch for Moonlight and for Selkies. An existing seat is not moved. A new seat is placed on the asking proxy's node when that GPU has room.

- `redirect` (the default). Selkies is a browser, so it gets HTTP 307 to the owning proxy (that pod's `cs1-resident` address, or the pod annotation `gamestream.local/advertise`, wrapped by `PUBLIC_HTTP_BASE`). Moonlight's control channel is also HTTP, and Qt 6 and the Android client will follow a 307, but that does not move the stream. RTSP and UDP are opened to the address that answered, not to the Location host. Moonlight stores `LocalIP` and `ExternalIP` from `serverinfo` and polls those next. Desktop tries the current address first, then the stored one. Android tries `LocalIP` first. The wrong proxy answers one `serverinfo` with the owning proxy's front address, then RSTs. The next poll fails here, succeeds on the owning proxy, and that becomes the stream address. Pairing is not redirected.
- `reset`: Moonlight gets a TCP RST (`SO_LINGER` 0, not a TLS close) so this address fails and the client tries the next one it already has. The browser gets the retry page instead of a 307.
- `proxy`: both are spliced to the pod IP. Moonlight only does this when the pod IP is already known; otherwise it uses the redirect behavior above. Prefer `redirect`. A spliced `serverinfo` or `launch` is rewritten on the way out: `LocalIP`, `uniqueid`, and the RTSP url use the host the client dialed, not the pod address Sunshine saw.

UDP and RTSP have no redirect. They show up on the owning proxy only after the client has moved.

One public VIP in front of every proxy is not enough for that hand-off. The address written into `serverinfo` is the kube-ovn address on `cs1-resident` (`<network>.<namespace>.ovn.kubernetes.io/ip_address`). Set `gamestream.local/advertise` on a proxy pod when that address is not what clients should store. The node IP is not advertised. `PUBLIC_HTTP_BASE` is `https://{host}` when Traefik terminates TLS for Selkies. Traefik stays on the back network.

## Build

From the repo root:

```bash
docker build -f image/Dockerfile -t gamestream:local .
docker build -f orchestrator/Dockerfile -t gs-orchestrator:local .
docker save gamestream:local gs-orchestrator:local | sudo ctr -n k8s.io images import -
```

Import the seat image on every GPU node. Import `ORCH_IMAGE` (`gs-orchestrator:local` unless you changed it) on every node that runs an orchestrator or a proxy. It is one image. It needs `python3-cryptography`, plus `rust`, `cargo`, and `gcc`. The container entrypoint reads `GS_ROLE`. `orchestrator` skips the relay and runs `orchestrator.py`. `proxy` compiles `gs-relay` from `/usr/local/src/gs-relay`, installs `/usr/local/bin/gs-relay`, and runs `moonlight_proxy.py`. The first proxy start is a release build; the proxy `startupProbe` allows five minutes. A later start of the same container filesystem skips the compile when the source stamp matches. `CERT_PROXY=false` does not use the relay. That mode still forwards the whole port span in Python. Redis is `REDIS_IMAGE` (`redis:7.4-alpine`). The cluster pulls that itself. It is not built from this repo.

## Apply

Follow [docs/deploy.md](docs/deploy.md). The short form, after the gate, the label, the images, and the passwords:

```bash
python3 deploy/render.py | kubectl apply -f -
kubectl -n "$NS" rollout status sts/gs-orchestrator
kubectl -n "$NS" rollout status sts/gs-redis
kubectl -n "$NS" rollout status ds/gs-proxy
```

`$NS` is `NAMESPACE`. The command fails while `CHANGE_ME` is still in `users.csv` or the `gs-cookie` Secret. `python3 deploy/render.py --allow-placeholders` prints the manifests anyway; do not apply that output. The orchestrator and the proxy refuse to start if the cookie secret or `ADMIN_PASSWORD` is still a placeholder, if `PERSIST_MOUNT` is not a mount, or if `PERSIST_MOUNT/.sunslop-volume` is missing. Create that empty file once on the host at `PERSIST_ROOT/.sunslop-volume`. A node-local `DirectoryOrCreate` does not have it, so it cannot mint a second certificate.

Point Traefik at Service `gs-proxy`, not at the orchestrator. The orchestrator Service is how the proxies reach `POST /v1/ensure`.

Homes land on `<PERSIST_ROOT>/<login>`. The shared directory is `<PERSIST_ROOT>/<COMMON_DIR>`, mounted read-only at `COMMON_MOUNT` in the seat (`/games`). The package layer is `<PERSIST_ROOT>/<LAYER_DIR>`. The init container mounts that directory at `LAYER_MOUNT` (`/gs-layer`) and is the only writer. The desktop mounts `usr` and `opt` from it read-only and does not see the layer directory. The proxy store is `<PERSIST_ROOT>/<PROXY_DIR>`. Both the proxy and the orchestrator mount `PERSIST_ROOT` at `PERSIST_MOUNT`. `COMMON_DIR`, `LAYER_DIR`, and `PROXY_DIR` are not legal logins. The desktop user inside the seat is `SEAT_USER` (`gsuser`, uid `SEAT_UID`), which is not a login name. The image's build-time account is overwritten from those values at boot, in the pod's private `/etc` only. Rebuild the seat image only if you change packages in the Dockerfile, not if you rename the account.

```bash
python3 deploy/render.py --time-slicing | kubectl apply -f -
```

The time-slicing ConfigMap is optional and lives in `GPU_OPERATOR_NAMESPACE`. It does nothing until the operator's device plugin uses it (`devicePlugin.config.name=gamestream-time-slicing`, `devicePlugin.config.default=any`) and the plugin pods restart. `GPU_COUNT` and `SESSIONS_PER_GPU` are the same keys the orchestrator reads. The orchestrator counts seats it has labeled per GPU and will not start one more than `SESSIONS_PER_GPU` on that GPU. The device plugin packs onto the lowest GPU id, and so does this picker, as long as these seats are the only GPU pods on the node.

## A connection

1. Moonlight hits any proxy's Sunshine ports. The certificate, not the port, picks the user. DNS needs an A record for every proxy, or one address that reaches only that node.
2. The proxy calls the orchestrator with its own node name. If that user's seat is already on this node, the proxy dials the pod IP. No second seat is created.
3. If the seat is on another node, the browser is sent to that node's proxy with HTTP 307. Moonlight is given that node's address in `serverinfo` and then reset, so its next poll lands there (`HTTP_FOREIGN`, default `redirect`). Nothing is spliced across nodes unless `HTTP_FOREIGN=proxy`.
4. If no seat exists, the orchestrator creates it on the asking node when a GPU there has room, otherwise on another proxy node. The asking proxy waits for Ready only when the seat is local.
5. The pod is Ready when labwc's socket exists. HTTPS control is then relayed. UDP and RTSP follow the client address recorded by that TLS session. `gs-relay` does that forwarding. Python does not bind those ports.
6. GPU index is the least loaded of `GPU_COUNT`, ties to the lower index, written to `gamestream.local/gpu` and `NVIDIA_VISIBLE_DEVICES`. With `DEVICE_PLUGIN=true` the plugin's allocation wins if it disagrees. Turn the plugin flag off only if the runtime actually honors that env var. nvkvm-kata on Kubernetes attaches a GPU because of the resource request.

Set `CERT_PROXY=false` to restore the older behavior: one external port span per user, a reset when the seat is on another node, and no certificate routing. Moonlight then has to be aimed at that user's external base.

The Selkies cookie `gs_session` is HMAC-signed, HttpOnly, 30 days (`COOKIE_TTL`). It is reissued on login and on each proxied response, so use extends it. `Secure` is set only when `X-Forwarded-Proto` is `https`, because the pod speaks HTTP and Traefik terminates TLS.

## Idle

Default 600s (`IDLE_SECONDS`) with no client traffic. An open Moonlight client keeps its seat: the HTTPS `serverinfo` poll counts, the same as launch, applist, Selkies, and the UDP stream. That poll does not create a seat. If the pod is already gone, the proxy answers `serverinfo` itself and the GPU stays free until launch or applist. Unpaired HTTP `serverinfo` does not count.

The orchestrators are the only reapers, and only the owner of a seat deletes it. Ownership and the liveliness stamp are keys in Redis, not memory in one process. A proxy posts the stamp to the orchestrator Service, which is a DNS record with one address per pod, so whichever orchestrator answers can update the stamp. It does not change the owner. The owner is the orchestrator that created the seat. Heartbeats are the same Redis. If `gs-orchestrator-0` stops beating, the next lowest ordinal (`gs-orchestrator-1`, then `gs-orchestrator-2`) adopts the seats it left. A live owner is not replaced just because a lower ordinal comes back.

Redis is the `redis:7.4-alpine` image, with Sentinel in the same pod. `CACHE_REPLICAS` 1 is one pod. 3 is a primary and two replicas: if the primary dies, Sentinel promotes a replica and the keys stay, so nothing is re-elected. Nothing is written to disk. If every Redis pod restarts, the board is empty. The orchestrators are still running, so the next pass lists the seat pods, writes heartbeats, and waits until that set of live orchestrators has sat still for `ORCH_STALE_SECONDS` (15s). Then the lowest ordinal adopts the ownerless seats. It does not invent a new activity time: the stamp is the pod annotation, unless a proxy has already posted a newer one. A seat that was already idle is deleted on the next reap. A seat that is still in use stays. Until that election finishes, a proxy rejects a new session and keeps one that already has a pod.

That is not a pause. Kata has no API that snapshots a VM, drops GPU memory and RAM, and restores the same processes. Checkpointing through the kubelet would also need `nodes/proxy`, which this ServiceAccount does not have. Delete frees the GPU and the memory. The game process is gone. Files under the home mount, Sunshine's pairing state, the shared package layer, the TPU scratchpad, and the UEFI variable store are not.

A later pause belongs behind `Seats.reap`. Do not widen the Role to get there.

## Secure Boot and the TPU

Seats ask the nvkvm VM for a Secure Boot capable firmware and a TPU emulator. The host side is [deploy/kata/gs_kata_shim.py](deploy/kata/gs_kata_shim.py), installed in front of the nvkvm QEMU shim. [docs/nvkvm-kata.md](docs/nvkvm-kata.md) is the node setup: `edk2-ovmf`, `enable_annotations`, and three lines in `shim.env`.

`KATA_FIRMWARE` is `OVMF_CODE.secboot.fd`. The variable store starts as `KATA_FIRMWARE_VARS` and is then `<PERSIST_ROOT>/<login>/uefi/OVMF_VARS.fd`. Out of the box that template is the empty store, so the firmware is Secure Boot capable and Secure Boot is off. An unsigned kernel still boots. To turn Secure Boot on, [deploy/kata/secureboot.sh](deploy/kata/secureboot.sh) makes a unique self-signed site cert, enrolls it as PK, KEK, and db (custom mode, not Setup Mode), and signs the EFI stub kernel and `nvkvm-guest.ko`. Point `GS_UEFI_TEMPLATE` at the enrolled store and set `GS_SB_ENFORCE=1`. The shim then refuses to fall back to an unsigned direct-kernel boot. Delete each login's existing `OVMF_VARS.fd` once, or the old store (Secure Boot off) is kept. `KATA_SECURE_BOOT=false` skips the firmware path.

The TPU is not a Cloud TPU. It is a 1 MiB int8 scratchpad at `/dev/virtio-ports/org.sunslop.tpu`. Its state file is `<PERSIST_ROOT>/<login>/tpu/state.bin` (`TPU_STATE_DIR`), on the same disk as the home directory, and it survives the pod. `TPU_EMULATION=false` skips it. The protocol is in the runtime doc.

## Desktop kernel

A seat is a kata VM. Steam, Proton, and Sunshine need a desktop guest kernel, not the compute fragment nvkvm builds by itself. Before `nvkvm-kata-install.sh`:

```bash
bash deploy/kata/apply-desktop-kernel.sh /path/to/nvkvm-kata
```

That splices [deploy/kata/desktop.x86_64.conf](deploy/kata/desktop.x86_64.conf) into `kata/fragments/gpu/nvkvm.x86_64.conf.in` and leaves a copy at `kata/fragments/gpu/desktop.x86_64.conf`. The build reads the spliced file only. Rebuild with `--graphics 1`. The kernel has to be **6.14 or newer** (ntsync). Every option is built-in. The kata rootfs does not contain `/lib/modules` for this kernel, so a module would never show up in the seat. `CONFIG_NTSYNC=m` would be the same as leaving it out.

The fragment asks for uinput (and `INPUT_MISC`, which hides it), evdev, joydev, HID/UHID, ntsync, FUSE passthrough, overlay, squashfs (xz and zstd, multi decompressor), binfmt_misc, userfaultfd, 32-bit emulation, a dummy ALSA card plus the sequencer, EFI variables, transparent hugepages, schedutil uclamp, preempt, and a 1 kHz tick. FUSE and overlay are already in Kata's own fs fragment; they are repeated so this build still requests them. `CONFIG_DRM` stays in nvkvm's graphics fragment. Do not set `CONFIG_MODULE_SIG_FORCE`. That would refuse `nvkvm-guest.ko`. `memfd_create` is not a fragment line: its prompt exists only with `CONFIG_EXPERT`, and turning that on would drop the syscalls Kata does not name. The apply script gives the symbol `default y` and regenerates the config with `olddefconfig` before the kernel compiles.

The node gate fails until `/proc/misc` has `uinput` and `ntsync`, `/proc/filesystems` has squashfs, overlay, and fuse, and `/proc/asound/cards` has the dummy card. uinput is a misc device (major 10). It is not a line in `/proc/devices`. The desktop container creates `/dev/ntsync`, `/dev/fuse`, `/dev/uhid`, and `/dev/uinput` with `mknod` (major 10) when the runtime `/dev` does not already have them. It does not mount a devtmpfs: that would need `CAP_SYS_ADMIN`. The shim strips an emulated VGA (`-vga none`, unless `GS_QEMU_VGA=keep`) so `/dev/dri/card0` is nvkvm's DRM node, which is what a Steam guest uses. `--graphics 1` merges `CONFIG_DRM`, `CONFIG_DRM_KMS_HELPER`, and `CONFIG_DRM_GEM_SHMEM_HELPER`. The desktop user is in the `audio` group. A pod that is already running does not pick a kernel change up. The GPU node has to rebuild the guest kernel. The first seat's init container copies `/usr`, `/etc`, and `/opt` into the shared layer, so `READY_TIMEOUT` is 900 seconds.

## Package layer

Startup packages are shared. They are not installed into each home, and they are not reinstalled on every boot.

The seat image stays the base desktop. An init container, `layer-init`, is the only writer. It flock-seeds `/usr`, `/etc`, and `/opt` into `<LAYER_MOUNT>` when the image changes, runs dnf, then copies `/etc` into an emptyDir private to this pod. That copy gets this pod's `resolv.conf`, `hosts`, `hostname`, and a new `machine-id`. The shared `/etc` is not mounted in the desktop container. The desktop mounts `usr` and `opt` from the layer **read-only**, and it does not mount the layer directory itself.

`<PERSIST_ROOT>/<LAYER_DIR>` is its own directory on the persistent disk, not a folder inside `COMMON_MOUNT`. The first seat to see a new image does the copy. Later seats take the flock, see the same image id and the same package list, and only publish the private `/etc`. Sixteen seats share one `/usr`.

The list is `/etc/gamestream/packages.list` in the image. If `<LAYER_MOUNT>/packages.list` exists, it replaces that list. One name per line. A package that is already in the rpmdb is skipped. A package this layer installed earlier and that is no longer on the list is `dnf remove`d. Nothing runs `dnf update`. `steam` enables RPM Fusion nonfree when it is missing. Steam itself stays commented out.

What is shared, and what is this pod's:

| Path | Who can write | Why |
|---|---|---|
| `/usr`, `/opt` | init container only | RPMs. The desktop mount is read-only, and the desktop has no `CAP_SYS_ADMIN`, so root cannot remount it. |
| `/etc` in the layer | init container only | Package config. Not mounted in the desktop. |
| `/etc` in the pod | this desktop | Private copy: DNS, hostname, machine-id, the unix account. Discarded with the pod. |
| `<SEAT_HOME>` | this login | Steam, Proton prefixes, Sunshine state, shader cache. One seat per login. |
| `COMMON_MOUNT` (`/games`) | nobody in the pod | Shared library, read-only. A seat cannot replace a binary another seat runs. Stage files on the host. Per-user installs go in the home. |
| `/tmp`, `/var/tmp`, `/var/log`, `/var/cache`, `/run` | this desktop | tmpfs, capped. Wayland, PipeWire, and supervisord live on `/run`. |

`<SEAT_HOME>/packages.list` is ignored. Do not delete `<PERSIST_ROOT>/<LAYER_DIR>`.

The desktop container is `readOnlyRootFilesystem`. Its added capabilities are `SYS_NICE`, `IPC_LOCK`, and `SYS_RESOURCE`, so the entrypoint can raise rtprio, memlock, and nofile before it drops to the desktop user. The game process does not get those capabilities. `allowPrivilegeEscalation` is false, so a setuid `bwrap` will not gain root; Steam Linux Runtime uses a user namespace instead (`CONFIG_USER_NS`). `GS_LAYER_ALLOW_UNMOUNTED=1` is only for a local `docker run` without this pod spec. `LAYER_MOUNT` has to be a mount in the init container.

## ServiceAccount

`ORCH_NAME` (`gs-orchestrator`) can `get`, `list`, `watch`, `create`, `delete`, and `patch` pods in `NAMESPACE`, and read pod logs. Nothing else, and no other namespace. Patch is the verb a pause annotation would use. Delete is what idle does.

`PROXY_NAME` (`gs-proxy`) has no Role. The DaemonSet sets `automountServiceAccountToken: false`.

## Direct connect

[deploy/seat-direct.yaml](deploy/seat-direct.yaml) is one seat with no proxy, for when you want the pod IP. It still mounts the shared public cert and writes the same Sunshine env, so a later proxy trusts it. Do not apply it for a user the orchestrator is also serving.

```bash
python3 deploy/render.py --seat
```

## Tests

```bash
python3 orchestrator/moonlight_proxy.py
python3 orchestrator/orchestrator.py --self-test
python3 image/seat-boot.py --self-test
python3 deploy/kata/gs_kata_shim.py --self-test
bash deploy/kata/apply-desktop-kernel.sh --self-test
bash deploy/kata/secureboot.sh --self-test
bash image/layer-init.sh --self-test
python3 deploy/render.py --self-test
cargo test --offline --manifest-path orchestrator/gs-relay/Cargo.toml
```

## Layout

| Path | Role |
|---|---|
| [orchestrator/orchestrator.py](orchestrator/orchestrator.py) | process the entrypoint starts when `GS_ROLE=orchestrator` |
| [orchestrator/moonlight_proxy.py](orchestrator/moonlight_proxy.py) | process the entrypoint starts when `GS_ROLE=proxy` |
| [orchestrator/entrypoint.sh](orchestrator/entrypoint.sh) | reads `GS_ROLE` and execs one of those two |
| [orchestrator/gs/seats.py](orchestrator/gs/seats.py) | seat lifecycle: create, place, idle delete |
| [orchestrator/gs/browser.py](orchestrator/gs/browser.py) | Selkies login and reverse proxy |
| [orchestrator/gs/api.py](orchestrator/gs/api.py) | orchestrator HTTP API |
| [orchestrator/gs/moonlight.py](orchestrator/gs/moonlight.py) | Sunshine TLS termination, HTTP reverse proxy, `/admin` |
| [orchestrator/gs/pairing.py](orchestrator/gs/pairing.py) | Moonlight pairing phases |
| [orchestrator/gs/protocol.py](orchestrator/gs/protocol.py) | serverinfo XML, pairing crypto, address rewrite |
| [orchestrator/gs/store.py](orchestrator/gs/store.py) | paired clients and the shared proxy certificate |
| [orchestrator/gs/relay.py](orchestrator/gs/relay.py) | starts the Rust UDP/RTSP relay |
| [orchestrator/gs-relay](orchestrator/gs-relay) | UDP and RTSP data plane, compiled on the proxy at start |
| [deploy/gs-config.yaml](deploy/gs-config.yaml) | site paths, account, ports, images |
| [deploy/render.py](deploy/render.py) | copies the ConfigMap into the other manifests |
| [deploy/orchestrator.yaml](deploy/orchestrator.yaml) | StatefulSet, headless Service, RBAC, users, cookie Secret |
| [deploy/cache.yaml](deploy/cache.yaml) | Redis and Sentinel, headless Service, back network |
| [deploy/proxy.yaml](deploy/proxy.yaml) | DaemonSet. Back NIC `ovn-default`, front NIC `cs1-resident`. No GPU request |
| [image/](image) | seat image: labwc, Sunshine, Selkies, package layer, seat-boot |
| [image/layer-init.sh](image/layer-init.sh) | init container: the only writer of the shared layer |
| [deploy/seat-direct.yaml](deploy/seat-direct.yaml) | one pod, no orchestrator |
| [deploy/time-slicing.yaml](deploy/time-slicing.yaml) | shares per GPU |
| [deploy/kata/gs_kata_shim.py](deploy/kata/gs_kata_shim.py) | Secure Boot pflash, `-vga none`, and the TPU emulator, in front of the nvkvm QEMU shim |
| [deploy/kata/secureboot.sh](deploy/kata/secureboot.sh) | site key, custom-mode enroll, sign the kernel and `nvkvm-guest.ko` |
| [deploy/kata/desktop.x86_64.conf](deploy/kata/desktop.x86_64.conf) | guest kernel fragment: uinput, ntsync, squashfs, 32-bit, dummy sound |
| [docs/deploy.md](docs/deploy.md) | ordered install: disk, kata, gate, label, apply |
| [docs/nvkvm-kata.md](docs/nvkvm-kata.md) | GPU-node runtime gate |
