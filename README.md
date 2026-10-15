# SunSlop

On-demand [Sunshine](https://github.com/LizardByte/Sunshine) and [Selkies](https://github.com/selkies-project/selkies) seats for Kubernetes. Nothing runs until a client connects. A proxy on each GPU node accepts the connection and asks one orchestrator to create the seat, preferably on that same node. Idle seats are deleted. Home directories and a shared package layer stay on disk.

Moonlight pairs with the proxy, not with a pod. The browser reaches Selkies through the same proxy. One shared certificate, generated on first start, is what every seat trusts.

Kubernetes object names stay `gs-orchestrator`, `gs-proxy`, and `gamestream` unless you change them in [deploy/gs-config.yaml](deploy/gs-config.yaml).

## What you need

- Kubernetes workers that have already passed [docs/nvkvm-kata.md](docs/nvkvm-kata.md). Do not apply a seat until that gate prints `GATE_OK` and the node is labeled `nvkvm.kata/ready=true`.
- A filesystem mounted at the same `PERSIST_ROOT` on every proxy node and on the orchestrator node.
- The seat image imported on every GPU node, and the orchestrator image on the orchestrator node and every proxy node. Both processes are that one image, selected with `GS_ROLE`.
- Traefik, or anything else that can route HTTP to Service `gs-proxy`. Moonlight does not go through that HTTP route. It dials the Sunshine ports on the proxy nodes.

## What listens where

Proxies are a hostNetwork DaemonSet, one per GPU node. They select `nvidia.com/gpu.present=true` and do not request `nvidia.com/gpu`, so they do not consume a seat. The orchestrator is one Deployment with no GPU and no host network. It is the only kube API client. Each seat runs Sunshine on `SUNSHINE_BASE` (47989) and Selkies on `SELKIES_PORT` (8082). Clients never pair with a pod.

| Client | Where it connects | What happens |
|---|---|---|
| Moonlight | Any proxy, `SUNSHINE_BASE` and `SUNSHINE_BASE` + `SUNSHINE_HTTPS_OFFSET` | Pairing and unpaired `serverinfo` stay on the proxy. TLS is terminated, the client certificate selects the login, and a second TLS session to the seat presents the shared proxy certificate. A seat on another node is not spliced. |
| Browser | Traefik to Service `gs-proxy` port `HTTP_PORT` (8080) | Password form, then a reverse proxy to that user's Selkies, only when the seat is on this proxy's node. |
| Admin | `http://<proxy>:HTTP_PORT/admin` | Type the PIN Moonlight is showing. Unpair a client. |

## Configure

[deploy/gs-config.yaml](deploy/gs-config.yaml) is the deploy. Paths, namespace, images, the seat's unix account, ports, and sizes are keys there. Do not search the scripts for a host path or a username.

Two values in that file are site paths, not secrets, and the committed defaults are only a starting point:

| Key | Committed default | Replace with |
|---|---|---|
| `NAMESPACE` | `gamestream` | Your namespace. |
| `PERSIST_ROOT` | `/var/lib/gamestream/persistent` | The shared host directory. The same string on every node. |

Logins and the Selkies passwords live in `users.csv` inside [deploy/orchestrator.yaml](deploy/orchestrator.yaml). The cookie HMAC key and the admin password live in the `gs-cookie` Secret in that same file. The committed values are placeholders. Replace them before `kubectl apply`. An empty `admin.password` leaves `/admin` open on a hostNetwork port.

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

`cookie.secret` must be at least 16 bytes. It is the HMAC key for the Selkies cookie and for the proxy-to-orchestrator API. `admin.password` only gates `/admin`. The admin cookie is an HMAC, not the password.

The password column is the Selkies login. `Directory.authenticate` checks it. With `CERT_PROXY=true` (the default) Moonlight ignores the third column and always dials `SUNSHINE_BASE`. The column remains so `CERT_PROXY=false` can fall back to one external port span per user: base−5 through base+21, shifted onto the pod's Sunshine ports. Ranges must not overlap, and `USER_PORT_STRIDE` must be at least 27.

`SamlAuthenticator.consume` is the only function a Keycloak ACS has to grow into. It returns a username that must already be in the file, and the existing cookie issuer does the rest. `/saml/acs` answers 501 until then.

`render.py` copies the ConfigMap into the namespace, the hostPaths, the Service ports, and the example `USER_BASE_n` rows. Kubernetes cannot do that by itself. Re-run it after any change. Do not `kubectl edit` the live ConfigMap and leave a volume on the old path.

## Pairing

Moonlight pairs with the proxy, once. The PIN is shown on the client. While that request is held open, open `/admin` on any proxy, type the four digits, and pick the login. The client certificate is stored with that user. The store is `<PERSIST_ROOT>/<PROXY_DIR>/store.json`, mounted at `<PERSIST_MOUNT>/<PROXY_DIR>/store.json`, so any proxy can finish a pairing another proxy started.

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

After TLS has identified the client, the source address is stuck to that pod, and only if the pod is on this node. Replies are rewritten back to the client. This is independent of the TLS socket. Two clients behind one NAT share a source address, so UDP follows whichever of them last completed TLS.

`serverinfo` is answered by the proxy when the seat is down, so a Moonlight poll does not boot a GPU. `applist`, `launch`, and the other HTTPS calls wait until the pod is Ready (labwc's socket), holding the already-finished handshake, but only when the seat is local. Moonlight's own HTTP read timeout is only a few seconds, so a remote placement returns immediately and the first click on the owning proxy starts the seat. The pod stays up across the retry. Budget is `READY_TIMEOUT` (180s) and it applies only to a local ensure.

## A connection on the wrong proxy

Proxies have the addresses clients can reach. The orchestrator may place the seat on a different GPU node. `HTTP_FOREIGN` is the same switch for Moonlight and for Selkies. An existing seat is not moved. A new seat is placed on the asking proxy's node when that GPU has room.

- `redirect` (the default). Selkies is a browser, so it gets HTTP 307 to the owning proxy (`hostIP`, or the pod annotation `gamestream.local/advertise`, wrapped by `PUBLIC_HTTP_BASE`). Moonlight's control channel is also HTTP, and Qt 6 and the Android client will follow a 307, but that does not move the stream. RTSP and UDP are opened to the address that answered, not to the Location host. Moonlight stores `LocalIP` and `ExternalIP` from `serverinfo` and polls those next. Desktop tries the current address first, then the stored one. Android tries `LocalIP` first. The wrong proxy answers one `serverinfo` with the owning proxy's address, then RSTs. The next poll fails here, succeeds on the owning proxy, and that becomes the stream address. Pairing is not redirected.
- `reset`: Moonlight gets a TCP RST (`SO_LINGER` 0, not a TLS close) so this address fails and the client tries the next one it already has. The browser gets the retry page instead of a 307.
- `proxy`: both are spliced to the pod IP. Moonlight only does this when the pod IP is already known; otherwise it uses the redirect behavior above. Prefer `redirect`. A spliced `serverinfo` or `launch` is rewritten on the way out: `LocalIP`, `uniqueid`, and the RTSP url use the host the client dialed, not the pod address Sunshine saw.

UDP and RTSP have no redirect. They show up on the owning proxy only after the client has moved.

One public VIP in front of every proxy is not enough for that hand-off. The address written into `serverinfo` has to be reachable as that node. Set `gamestream.local/advertise` on each proxy pod when the node IP is not the address clients dial. `PUBLIC_HTTP_BASE` is `https://{host}` when Traefik terminates TLS for Selkies.

## Build

From the repo root:

```bash
docker build -f image/Dockerfile -t gamestream:local .
docker build -f orchestrator/Dockerfile -t gs-orchestrator:local .
docker save gamestream:local gs-orchestrator:local | sudo ctr -n k8s.io images import -
```

Import the seat image on every GPU node. The orchestrator image has to be on the orchestrator's node and on every proxy node. It needs `python3-cryptography`, which the image installs.

## Apply

```bash
python3 deploy/render.py | kubectl apply -f -
kubectl -n "$NS" rollout status deploy/gs-orchestrator
kubectl -n "$NS" rollout status ds/gs-proxy
```

`$NS` is `NAMESPACE`. Point Traefik at Service `gs-proxy`, not at the orchestrator. The orchestrator Service is how the proxies reach `POST /v1/ensure`.

Homes land on `<PERSIST_ROOT>/<login>`. The shared directory is `<PERSIST_ROOT>/<COMMON_DIR>`, mounted at `COMMON_MOUNT` in the seat (`/games`). The package layer is `<PERSIST_ROOT>/<LAYER_DIR>`, mounted at `LAYER_MOUNT` (`/gs-layer`). The proxy store is `<PERSIST_ROOT>/<PROXY_DIR>`. Both the proxy and the orchestrator mount `PERSIST_ROOT` at `PERSIST_MOUNT`. `COMMON_DIR`, `LAYER_DIR`, and `PROXY_DIR` are not legal logins. The desktop user inside the seat is `SEAT_USER` (`gsuser`, uid `SEAT_UID`), which is not a login name. The image's build-time account is overwritten from those values at boot. Rebuild the seat image only if you change packages in the Dockerfile, not if you rename the account.

```bash
python3 deploy/render.py --time-slicing | kubectl apply -f -
```

The time-slicing ConfigMap is optional and lives in `GPU_OPERATOR_NAMESPACE`. It does nothing until the operator's device plugin uses it (`devicePlugin.config.name=gamestream-time-slicing`, `devicePlugin.config.default=any`) and the plugin pods restart. `GPU_COUNT` and `SESSIONS_PER_GPU` are the same keys the orchestrator reads. The orchestrator counts seats it has labeled per GPU and will not start one more than `SESSIONS_PER_GPU` on that GPU. The device plugin packs onto the lowest GPU id, and so does this picker, as long as these seats are the only GPU pods on the node.

## A connection

1. Moonlight hits any proxy's Sunshine ports. The certificate, not the port, picks the user. DNS needs an A record for every proxy, or one address that reaches only that node.
2. The proxy calls the orchestrator with its own node name. If that user's seat is already on this node, the proxy dials the pod IP. No second seat is created.
3. If the seat is on another node, the browser is sent to that node's proxy with HTTP 307. Moonlight is given that node's address in `serverinfo` and then reset, so its next poll lands there (`HTTP_FOREIGN`, default `redirect`). Nothing is spliced across nodes unless `HTTP_FOREIGN=proxy`.
4. If no seat exists, the orchestrator creates it on the asking node when a GPU there has room, otherwise on another proxy node. The asking proxy waits for Ready only when the seat is local.
5. The pod is Ready when labwc's socket exists. HTTPS control is then relayed. UDP and RTSP follow the client address recorded by that TLS session.
6. GPU index is the least loaded of `GPU_COUNT`, ties to the lower index, written to `gamestream.local/gpu` and `NVIDIA_VISIBLE_DEVICES`. With `DEVICE_PLUGIN=true` the plugin's allocation wins if it disagrees. Turn the plugin flag off only if the runtime actually honors that env var. nvkvm-kata on Kubernetes attaches a GPU because of the resource request.

Set `CERT_PROXY=false` to restore the older behavior: one external port span per user, a reset when the seat is on another node, and no certificate routing. Moonlight then has to be aimed at that user's external base.

The Selkies cookie `gs_session` is HMAC-signed, HttpOnly, 30 days (`COOKIE_TTL`). It is reissued on login and on each proxied response, so use extends it. `Secure` is set only when `X-Forwarded-Proto` is `https`, because the pod speaks HTTP and Traefik terminates TLS.

## Idle

Default 600s (`IDLE_SECONDS`) with no proxied bytes. A `serverinfo` poll does not count, so an open Moonlight window does not pin a GPU. Launch, applist, Selkies, and the UDP stream do.

The orchestrator is the only reaper. It deletes idle seats on every node. A proxy that is carrying the stream patches `gamestream.local/last-activity` (at most every 30 seconds). The seat stays while that annotation is fresh.

That is not a pause. Kata has no API that snapshots a VM, drops GPU memory and RAM, and restores the same processes. Checkpointing through the kubelet would also need `nodes/proxy`, which this ServiceAccount does not have. Delete frees the GPU and the memory. The game process is gone. Files under the home mount, Sunshine's pairing state, and the shared package layer are not.

A later pause belongs behind `Seats.reap`. Do not widen the Role to get there.

## Package layer

Startup packages are shared. They are not installed into each home, and they are not reinstalled on every boot.

The seat image stays the base desktop. On start, as root, before supervisord, the entrypoint bind-mounts `<LAYER_MOUNT>/usr` and `<LAYER_MOUNT>/etc` over `/usr` and `/etc`. The dnf cache and `installed.list` sit beside them. The default mount is `/gs-layer`.

`<PERSIST_ROOT>/<LAYER_DIR>` is its own directory on the persistent disk, not a folder inside `COMMON_MOUNT`. The first seat to see a new image copies `/usr` and `/etc` into that tree and runs dnf. Later seats take the flock, see the same image id and the same package list, and only bind-mount. That is a few seconds. Sixteen seats share one copy.

The list is `/etc/gamestream/packages.list` in the image. If `<LAYER_MOUNT>/packages.list` exists, it replaces that list. One name per line. A package that is already in the rpmdb is skipped. A package this layer installed earlier and that is no longer on the list is `dnf remove`d. Nothing runs `dnf update`. `steam` enables RPM Fusion nonfree when it is missing.

This is a real directory, not an overlay. The CRI-O root is often a network filesystem via FUSE, and the guest sees it through virtio-fs. Kernel overlay will not use either as an upper directory, and a shared overlay upper cannot be mounted by every seat at once. A bind mount is just files. POSIX `flock` on that filesystem is the lock around seed and dnf. `/etc/resolv.conf`, `hosts`, `hostname`, and `machine-id` are bind-mounted back from the pod so one seat's DNS is not written into the shared `/etc`.

`<SEAT_HOME>/packages.list` is ignored. Personal apps go in the home directory (a user prefix, a wine or lutris prefix, a binary under `~/bin`). They are not root RPMs on the shared layer. Do not delete `<PERSIST_ROOT>/<LAYER_DIR>`.

The seat still needs `CAP_SYS_ADMIN` for the bind mounts. `LAYER_MOUNT` has to be a mount. `GS_LAYER_ALLOW_UNMOUNTED=1` is only for a local run without that volume.

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
```

## Layout

| Path | Role |
|---|---|
| [orchestrator/orchestrator.py](orchestrator/orchestrator.py) | seats, placement, Selkies login, idle, orchestrator API |
| [orchestrator/moonlight_proxy.py](orchestrator/moonlight_proxy.py) | Sunshine TLS, pairing, UDP, `/admin`, shared cert |
| [deploy/gs-config.yaml](deploy/gs-config.yaml) | site paths, account, ports, images |
| [deploy/render.py](deploy/render.py) | copies the ConfigMap into the other manifests |
| [deploy/orchestrator.yaml](deploy/orchestrator.yaml) | Deployment, RBAC, users, cookie Secret |
| [deploy/proxy.yaml](deploy/proxy.yaml) | DaemonSet, hostNetwork, no GPU request |
| [image/](image) | seat image: labwc, Sunshine, Selkies, package layer, seat-boot |
| [deploy/seat-direct.yaml](deploy/seat-direct.yaml) | one pod, no orchestrator |
| [deploy/time-slicing.yaml](deploy/time-slicing.yaml) | shares per GPU |
| [docs/nvkvm-kata.md](docs/nvkvm-kata.md) | GPU-node runtime gate |
