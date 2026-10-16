# Deploy SunSlop

Do these steps in order. The gate in step 6 has to pass before you label a node, and the label has to be on the node before the proxy will start. `python3 deploy/render.py` will not print manifests while a secret or a Selkies password still contains `CHANGE_ME`.

This is a remote desktop. It is not a medical-record system. Home directories, Moonlight pairing, the UEFI variable store, and the TPU scratchpad are ordinary files on the shared disk. Do not put the GPU node addresses on the public internet. The client network is the only place that should reach the ports in step 10.

Two longer references, if a step here is not enough: [nvkvm-kata.md](nvkvm-kata.md) for the runtime, and the [README](../README.md) for ports, idle, and the package layer.

## 1. Cluster that is already there

- Kubernetes, with the NVIDIA GPU Operator in its normal mode. Host `nvidia` module, `nvidia.com/gpu` advertised by the device plugin.
- Do not enable `sandboxWorkloads` and do not bind the GPUs to `vfio-pci`. That takes the card away from nvkvm. Details are in [nvkvm-kata.md](nvkvm-kata.md).
- A filesystem you can mount at the same path on the orchestrator node and on every GPU node. NFS with `root_squash` will not work: the seat `chown`s the home directory to the desktop user.
- `ctr` (or an equivalent) so you can import images on the nodes. The manifests use `imagePullPolicy: IfNotPresent` and the default names are local tags, not a registry.

## 2. Shared disk

Pick the host path. The committed value is `/var/lib/gamestream/persistent`. If you change it, change `PERSIST_ROOT` in [deploy/gs-config.yaml](../deploy/gs-config.yaml) and `GS_PERSIST_ROOT` in step 5 so they are the same string.

On the shared filesystem, once:

```bash
install -d -m 0755 /var/lib/gamestream/persistent
touch /var/lib/gamestream/persistent/.sunslop-volume
```

Mount that same filesystem at that same path on the node that will run `gs-orchestrator` and on every GPU node. `findmnt /var/lib/gamestream/persistent` on each of those nodes must show the same device. The orchestrator refuses to start when that directory is not a mount inside the pod, or when `.sunslop-volume` is missing. `DirectoryOrCreate` would otherwise create a private directory and a second certificate.

`GS_PERSIST_ALLOW_UNMOUNTED=1` skips the check. It is for a local process on a workstation, not for this cluster.

## 3. Site values and passwords

Edit [deploy/gs-config.yaml](../deploy/gs-config.yaml):

| Key | What to set |
|---|---|
| `NAMESPACE` | The namespace. The gate pod in step 6 uses the same one. |
| `PERSIST_ROOT` | The host path from step 2. |
| `ORCH_IMAGE`, `SEAT_IMAGE` | The tags you import in step 8, if not `gs-orchestrator:local` and `gamestream:local`. |
| `GPU_COUNT` | How many GPUs each worker has. |
| `SESSIONS_PER_GPU` | Seats per GPU. The orchestrator will not start one more than this. |
| `PUBLIC_HTTP_BASE` | `https://{host}` when Traefik terminates TLS for the browser. Leave empty to use `http://{host}:HTTP_PORT`. |
| `IDLE_SECONDS` | How long a seat stays up with no client traffic. Default 600. |

Leave the port offsets alone unless you also change the Sunshine build in the seat image.

Edit [deploy/orchestrator.yaml](../deploy/orchestrator.yaml):

- `users.csv`: one line per login, `username,password,base_port`. The password is the Selkies login. Usernames are lowercase, start with a letter, and are at most 40 characters. `common`, `gs-layer`, and `proxy` are not logins. With `CERT_PROXY=true` (the default) Moonlight does not use the port column; every client dials `SUNSHINE_BASE`.
- `gs-cookie`: replace both strings. `cookie.secret` is the HMAC key for the browser cookie and for the proxy-to-orchestrator API, at least 16 bytes. `admin.password` is the `/admin` password. An empty admin password is refused at startup, because `/admin` would be open on the node.

```bash
python3 deploy/render.py --allow-placeholders >/dev/null   # still prints; do not apply this
python3 deploy/render.py >/dev/null                        # must succeed before step 9
```

The second command fails until every `CHANGE_ME` value is gone.

## 4. GPU node: nvkvm-kata

On every CentOS Stream 9 (or other RHEL-family) GPU worker, as root. The full host checks, the containerd snippets, and what not to change in the GPU Operator are in [nvkvm-kata.md](nvkvm-kata.md).

```bash
dnf install -y git
dnf config-manager --set-enabled crb
git clone https://github.com/reindertpelsma/nvkvm-kata
cd nvkvm-kata
bash /path/to/SunSlop/deploy/kata/apply-desktop-kernel.sh .
sudo scripts/nvkvm-kata-install.sh \
  --install-kata \
  --install-deps \
  --graphics 1 \
  --containerd-cri \
  --no-docker
systemctl restart containerd
```

`--graphics 1` is required. The desktop fragment does not turn `CONFIG_DRM` on by itself. After any GPU Operator upgrade, confirm the `nvkvm-kata` block is still in containerd's config and that `disabled_plugins` does not contain `cri`.

## 5. GPU node: shim, OVMF, Kata config

Still on the GPU node. The paths have to match `KATA_FIRMWARE`, `KATA_FIRMWARE_VARS`, and `PERSIST_ROOT`.

```bash
dnf install -y edk2-ovmf
install -m 0755 /path/to/SunSlop/deploy/kata/gs_kata_shim.py /usr/local/bin/gs-kata-shim
python3 /usr/local/bin/gs-kata-shim --self-test
```

In `/etc/kata-containers/configuration-nvkvm.toml`:

```toml
[hypervisor.qemu]
path = "/usr/local/bin/gs-kata-shim"
enable_annotations = ["default_vcpus", "default_memory", "firmware", "kernel_params"]
```

Keep any annotation name that was already listed. If `valid_hypervisor_paths` is non-empty, add `/usr/local/bin/gs-kata-shim` to it. `kernel_params` is trusted: a pod on this RuntimeClass can name a directory under `GS_PERSIST_ROOT`. The orchestrator is the only thing that creates seat pods. Listing `firmware` without `kernel_params` leaves Kata on `-bios`, and the shim never sees the variable store.

Append to `/etc/nvkvm-kata/shim.env` (do not remove the `NVKVM_*` lines the installer wrote):

```
GS_PERSIST_ROOT=/var/lib/gamestream/persistent
GS_UEFI_CODE=/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd
GS_UEFI_TEMPLATE=/usr/share/edk2/ovmf/OVMF_VARS.fd
NVKVM_SHIM=/opt/nvkvm-kata/bin/nvkvm-qemu-shim
```

Use the empty `OVMF_VARS.fd`, not `OVMF_VARS.secboot.fd`. The secboot store enrolls keys and then will not boot this unsigned guest kernel. Secure Boot stays capable and off. Enrolling keys later is per login, at `<PERSIST_ROOT>/<login>/uefi/OVMF_VARS.fd`, and deleting that file returns the login to the empty template.

`KATA_SECURE_BOOT=false` or `TPU_EMULATION=false` in the ConfigMap skips that half. The TPU is a 1 MiB scratchpad on a virtio serial port, not a Cloud TPU.

## 6. Prove the node

Do this before the node is labeled, and before step 9. SunSlop's RuntimeClass carries `nvkvm.kata/ready=true`. The admission controller copies that selector onto every pod that uses the class, and the kubelet rejects the pod on an unlabeled node even when `nodeName` is set. The gate has to use a RuntimeClass **without** that selector.

Apply this once, or replace the class if step 9 already ran:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: nvkvm-kata
handler: nvkvm-kata
overhead:
  podFixed:
    cpu: "250m"
    memory: 512Mi
```

Then run the gate pod from [nvkvm-kata.md](nvkvm-kata.md) ("Prove the runtime before you label the node"). `GATE_OK` is the only passing line. You need `/dev/dri/card0`, `uinput` and `ntsync` in `/proc/misc`, squashfs, overlay, and fuse in `/proc/filesystems`, and a dummy card in `/proc/asound/cards`. On the host, `nvidia-smi -L` must still show the GPUs on the `nvidia` driver, not `vfio-pci`.

The gate does not boot OVMF. It does not prove the shim. The first real seat does: `ls /sys/firmware/efi` and `ls /dev/virtio-ports/org.sunslop.tpu` inside that seat. If the seat never becomes Ready after step 5, set `KATA_SECURE_BOOT=false`, re-render, and leave the TPU on.

## 7. Label the node

```bash
kubectl label node "$NODE" nvkvm.kata/ready=true
```

Repeat steps 4 through 7 for each GPU node. The proxy DaemonSet requires both `nvidia.com/gpu.present=true` and `nvkvm.kata/ready=true`. A GPU node without the kata label does not get a proxy, and the orchestrator will not place a seat there.

## 8. Images

From the repo root, then on every node that needs the image. The seat image goes on every GPU node. The orchestrator image goes on the orchestrator's node and on every GPU node (the proxy is that image with `GS_ROLE=proxy`).

```bash
docker build -f image/Dockerfile -t gamestream:local .
docker build -f orchestrator/Dockerfile -t gs-orchestrator:local .
docker save gamestream:local gs-orchestrator:local | sudo ctr -n k8s.io images import -
```

The proxy compiles `gs-relay` the first time it starts. The startup probe allows five minutes for that. A later start of the same container filesystem skips the compile when the source stamp matches.

## 9. Apply

```bash
python3 deploy/render.py | kubectl apply -f -
NS=gamestream   # NAMESPACE
kubectl -n "$NS" rollout status deploy/gs-orchestrator
kubectl -n "$NS" rollout status ds/gs-proxy
kubectl -n "$NS" logs deploy/gs-orchestrator | head
```

The orchestrator log line `persist: ...` is the mount it actually got. If a proxy stays Pending, the node is missing one of the two labels from step 7.

This apply replaces the RuntimeClass from step 6 and adds the node selector. That is what you want once the nodes are labeled.

Point Traefik at Service `gs-proxy`, port `HTTP_PORT` (8080), not at the orchestrator. The orchestrator Service is only how the proxies call `POST /v1/ensure`.

Optional, and idle until the device plugin is told to use it:

```bash
python3 deploy/render.py --time-slicing | kubectl apply -f -
```

Do not apply `python3 deploy/render.py --seat`. That is one pod with no proxy, for debugging a single login. The orchestrator must not also be serving that login.

## 10. Ports

Moonlight does not go through Traefik. Each GPU node's address has to accept the Sunshine family. One public VIP in front of every proxy breaks the hand-off: the address written into `serverinfo` has to be that node. Set pod annotation `gamestream.local/advertise` on a proxy when the node IP is not the address clients dial.

With `SUNSHINE_BASE` 47989, open these from the client network to every GPU node:

| Port | Proto | Why |
|---|---|---|
| 47984 | TCP | HTTPS. Client certificate, then the seat. |
| 47989 | TCP | HTTP pairing and unpaired `serverinfo`. |
| 47998, 47999, 48000, 48002, 48010 | UDP | Video, control, audio, the extra stream, and the RTSP UDP port. |
| 48010 | TCP | RTSP. |
| 8080 | TCP | Selkies and `/admin`. Traefik may be the path browsers use. The process still binds port 8080 on the node, so firewall this to the client network too. |

Do not publish 47990. That is Sunshine's own web UI, and only the seat listens.

`/admin` pairs a Moonlight device to a login. Treat `admin.password` as a staff credential. Anyone who can open it can attach a client certificate to a user.

## 11. Pair

1. In Moonlight, add the address of any GPU node and start pairing. The PIN is on the client. The request waits up to 10 minutes.
2. Open `http://<that-node>:8080/admin` (or the Traefik URL), enter `admin.password`, type the four digits, and pick the login.
3. The certificate is stored at `<PERSIST_ROOT>/proxy/store.json`. The public half is `<PERSIST_ROOT>/proxy/proxy-client.crt`. Every seat mounts that file and trusts it at boot. `/admin` shows whether each login's state file contains it.
4. Open the host in Moonlight. `applist` or launch is what creates the seat. A `serverinfo` poll does not. The first seat copies `/usr` into the shared layer, so the first connection can take most of `READY_TIMEOUT` (900 seconds). The pod is Ready when labwc's socket exists.
5. An open Moonlight window keeps that seat up: the HTTPS `serverinfo` poll resets the idle timer. Closing Moonlight, with no browser session and no UDP, deletes the pod after `IDLE_SECONDS`. The home directory remains.

## 12. After it is up

- A second node is steps 4 through 7, the same images, and the same disk. Re-apply only if a manifest changed.
- An NVIDIA driver upgrade needs `nvkvm-kata-gpu-cdi discover --force` from the nvkvm-kata checkout, then the gate again. Do not trust a label left over from the previous driver.
- Deleting a seat pod is not a pause. The game process is gone. Files under the home directory are not.
- The orchestrator can `get`, `list`, `watch`, `create`, `delete`, and `patch` pods in this namespace, and read pod logs. The proxy has no kube token.
