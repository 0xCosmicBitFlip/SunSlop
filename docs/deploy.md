# Deploy SunSlop

Do these steps in order. The gate in step 6 has to pass before you label a node, and the label has to be on the node before the proxy will start. `python3 deploy/render.py` will not print manifests while a secret or a Selkies password still contains `CHANGE_ME`.

This is a remote desktop. It is not a medical-record system. Home directories, Moonlight pairing, the UEFI variable store, and the TPU scratchpad are ordinary files on the shared disk. Do not put the GPU node addresses on the public internet. The client network is the only place that should reach the ports in step 10.

Two longer references, if a step here is not enough: [nvkvm-kata.md](nvkvm-kata.md) for the runtime, and the [README](../README.md) for ports, idle, and the package layer.

## 1. Cluster that is already there

- Kubernetes, with the NVIDIA GPU Operator in its normal mode. Host `nvidia` module, `nvidia.com/gpu` advertised by the device plugin.
- Kube-OVN is the pod network, and Multus is installed. Two networks already exist. The back network is the subnet the `default` namespace uses (`ovn-default` unless you moved that namespace). The front network is the kube-ovn attachment `cs1-resident`: a NetworkAttachmentDefinition of that name in the `default` namespace, provider `cs1-resident.default.ovn`, and a Subnet of the same name. Clients dial the front address. The orchestrator, the proxy, and the seats talk to each other on the back network. The proxy is the only pod that has both.
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
| `OVN_BACK_SUBNET` | The subnet the `default` namespace uses. Leave `ovn-default` if that is still it. |
| `OVN_FRONT_NETWORK` | The client attachment. Leave `cs1-resident` if that NAD and subnet already have that name. |
| `OVN_FRONT_NAD_NS` | Namespace of that NetworkAttachmentDefinition. `default` unless you put the NAD somewhere else. |
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

Skip this next block for a first bring-up. Secure Boot stays capable and off, and the unsigned kernel boots. If this site will boot the guest with Secure Boot on, generate the key first. The install below compiles the kernel, and the kernel has to trust the cert.

```bash
dnf install -y python3-virt-firmware sbsigntools openssl
install -d -m 0700 /etc/nvkvm-kata
bash /path/to/SunSlop/deploy/kata/secureboot.sh --init --dir /etc/nvkvm-kata/secureboot
bash /path/to/SunSlop/deploy/kata/secureboot.sh --fragment --dir /etc/nvkvm-kata/secureboot \
  > /etc/nvkvm-kata/secureboot/module-sig.conf
```

`module-sig.conf` is not spliced by `apply-desktop-kernel.sh`. After the clone below, append that file to `kata/fragments/gpu/nvkvm.x86_64.conf.in` before `nvkvm-kata-install.sh`, or the guest will not trust modules signed by this key. Do not add `CONFIG_MODULE_SIG_FORCE` until `nvkvm-guest.ko` is signed (step 5). The key stays on the operator machine. It is not in git, and it is not copied into a seat.

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

`--graphics 1` is required. The desktop fragment does not turn `CONFIG_DRM` on by itself. The graphics fragment has to set `CONFIG_DRM`, `CONFIG_DRM_KMS_HELPER`, and `CONFIG_DRM_GEM_SHMEM_HELPER`. `apply-desktop-kernel.sh` checks that file. The shim passes `-vga none` so an emulated VGA does not take `/dev/dri/card0` from the virtio-nvgpu node. After any GPU Operator upgrade, confirm the `nvkvm-kata` block is still in containerd's config and that `disabled_plugins` does not contain `cri`.

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

Use the empty `OVMF_VARS.fd`, not `OVMF_VARS.secboot.fd`. The secboot store enrolls Microsoft's keys and then will not boot this unsigned guest kernel. With the empty store, Secure Boot stays capable and off. The per-login copy is `<PERSIST_ROOT>/<login>/uefi/OVMF_VARS.fd`. The shim copies the template only when that file is missing. Deleting it returns the login to whatever the template is now.

`KATA_FIRMWARE_VARS` and `GS_UEFI_TEMPLATE` are the same path. The pod does not pass the template. Only `shim.env` does.

To turn Secure Boot on, after the kernel from step 4 exists, sign it with the site key and enroll that key in custom mode. Custom mode means a PK is present, so the firmware is not in Setup Mode. The same cert is PK, KEK, and db. This replaces the empty template. Do it before the first seat if you do not want to delete variable stores later.

```bash
# vmlinuz and nvkvm-guest.ko are the paths the install just wrote.
bash /path/to/SunSlop/deploy/kata/secureboot.sh --sign-kernel \
  --dir /etc/nvkvm-kata/secureboot /path/vmlinuz
bash /path/to/SunSlop/deploy/kata/secureboot.sh --sign-module \
  --dir /etc/nvkvm-kata/secureboot \
  --kbuild /path/kata-linux-nvkvm /path/nvkvm-guest.ko
bash /path/to/SunSlop/deploy/kata/secureboot.sh --enroll \
  --dir /etc/nvkvm-kata/secureboot \
  --template /usr/share/edk2/ovmf/OVMF_VARS.fd \
  --out /etc/nvkvm-kata/secureboot/OVMF_VARS.custom.fd
```

Point Kata's `kernel` at the signed EFI stub (`vmlinuz.signed`), not a raw bzImage. OVMF checks that `-kernel` image only when the variable store has Secure Boot on. Then change `shim.env`:

```
GS_UEFI_TEMPLATE=/etc/nvkvm-kata/secureboot/OVMF_VARS.custom.fd
GS_SB_ENFORCE=1
```

Set `KATA_FIRMWARE_VARS` to that same path and re-render when you apply. `GS_SB_ENFORCE=1` makes the shim exit instead of dropping the pflash and booting unsigned. If any login already has `OVMF_VARS.fd`, delete it once. An old store still has Secure Boot off, and the shim will not overwrite it.

`KATA_SECURE_BOOT=false` or `TPU_EMULATION=false` in the ConfigMap skips that half. The TPU is a 1 MiB scratchpad on a virtio serial port, not a Cloud TPU. The shim also passes `-vga none` unless `GS_QEMU_VGA=keep`. That is what keeps the nvkvm DRM node as `/dev/dri/card0`.

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

From the repo root, then on every node that needs the image. The seat image goes on every GPU node. One control-plane image (`ORCH_IMAGE`) goes on the orchestrator's node and on every GPU node. The proxy DaemonSet uses that same image. `GS_ROLE=orchestrator` starts `orchestrator.py`. `GS_ROLE=proxy` compiles `gs-relay` and starts `moonlight_proxy.py`.

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

The orchestrator log line `persist: ...` is the mount it actually got. If a proxy stays Pending, the node is missing one of the two labels from step 7, or `cs1-resident` is not a NetworkAttachmentDefinition in `OVN_FRONT_NAD_NS`. A seat that starts on a different subnet than the proxy cannot be reached: both must be on `OVN_BACK_SUBNET`. If kube-ovn has already bound this namespace to some other subnet, add `${NAMESPACE}` to the back subnet's `spec.namespaces` and take it off the other one.

This apply replaces the RuntimeClass from step 6 and adds the node selector. That is what you want once the nodes are labeled.

Point Traefik at Service `gs-proxy`, port `HTTP_PORT` (8080), not at the orchestrator. That Service is on the back network. The orchestrator Service is only how the proxies call `POST /v1/ensure`, also on the back network. Do not point Moonlight at either Service.

Optional, and idle until the device plugin is told to use it:

```bash
python3 deploy/render.py --time-slicing | kubectl apply -f -
```

Do not apply `python3 deploy/render.py --seat`. That is one pod with no proxy, for debugging a single login. The orchestrator must not also be serving that login.

## 10. Ports

Moonlight does not go through Traefik, and it does not dial the node address. Each proxy pod has a second address on `cs1-resident`. That is the address written into `serverinfo`. One public VIP in front of every proxy breaks the hand-off. `gamestream.local/advertise` on a proxy pod replaces the kube-ovn front address when clients should store something else. The node `hostIP` is not used.

The proxy listens on all of its interfaces. Packets from clients arrive on the front NIC. Replies use that same address. The default route stays on the back NIC, so the proxy still reaches the orchestrator Service and the seat pod IPs. Do not put the Sunshine ports on the back subnet's firewall policy for clients. Clients are on the front network.

With `SUNSHINE_BASE` 47989, open these from the client network to each proxy's `cs1-resident` address:

| Port | Proto | Why |
|---|---|---|
| 47984 | TCP | HTTPS. Client certificate, then the seat. |
| 47989 | TCP | HTTP pairing and unpaired `serverinfo`. |
| 47998, 47999, 48000, 48002, 48010 | UDP | Video, control, audio, the extra stream, and the RTSP UDP port. |
| 48010 | TCP | RTSP. |
| 8080 | TCP | Selkies and `/admin`, if a browser dials the front address directly. Traefik on the back network is the usual path, and it uses Service `gs-proxy` instead of this address. |

Do not publish 47990. That is Sunshine's own web UI, and only the seat listens.

`/admin` pairs a Moonlight device to a login. Treat `admin.password` as a staff credential. Anyone who can open it can attach a client certificate to a user.

Confirm the split after the first proxy is Running:

```bash
kubectl -n gamestream get pod -l app=gs-proxy -o jsonpath='{range .items[*]}{.spec.nodeName}{" back="}{.metadata.annotations.ovn\.kubernetes\.io/ip_address}{" front="}{.metadata.annotations.cs1-resident\.default\.ovn\.kubernetes\.io/ip_address}{"\n"}{end}'
```

`back` and `front` must be different addresses. Moonlight uses `front`.

## 11. Pair

1. In Moonlight, add the `cs1-resident` address of any proxy and start pairing. The PIN is on the client. The request waits up to 10 minutes. The node IP will not answer.
2. Open `http://<front-address>:8080/admin` (or the Traefik URL on the back network), enter `admin.password`, type the four digits, and pick the login.
3. The certificate is stored at `<PERSIST_ROOT>/proxy/store.json`. The public half is `<PERSIST_ROOT>/proxy/proxy-client.crt`. Every seat mounts that file and trusts it at boot. `/admin` shows whether each login's state file contains it.
4. Open the host in Moonlight. `applist` or launch is what creates the seat. A `serverinfo` poll does not. The seat's init container is the only writer of the shared package layer. The first one copies `/usr`, `/etc`, and `/opt` and may install RPMs, so the first connection can take most of `READY_TIMEOUT` (900 seconds). The desktop container then mounts `/usr` and `/opt` read-only and a private `/etc`. It has no `CAP_SYS_ADMIN`, so root in the seat cannot remount the layer or change `/games`. The pod is Ready when labwc's socket exists.
5. An open Moonlight window keeps that seat up: the HTTPS `serverinfo` poll resets the idle timer. Closing Moonlight, with no browser session and no UDP, deletes the pod after `IDLE_SECONDS`. The home directory remains.

## 12. After it is up

- A second node is steps 4 through 7, the same images, and the same disk. Re-apply only if a manifest changed.
- An NVIDIA driver upgrade needs `nvkvm-kata-gpu-cdi discover --force` from the nvkvm-kata checkout, then the gate again. Do not trust a label left over from the previous driver.
- Deleting a seat pod is not a pause. The game process is gone. Files under the home directory are not. The shared layer is not. A seat cannot edit either of the other two: `/usr` and `/opt` are read-only, `/games` is read-only, and the layer directory is not mounted in the desktop container. Writable paths are the login's home and the tmpfs mounts `/tmp`, `/var/tmp`, `/var/log`, `/var/cache`, and `/run`.
- Package changes go in `<PERSIST_ROOT>/<LAYER_DIR>/packages.list`, or in the image's `image/packages.list`. The next new seat's init container applies them. A running seat does not.
- The desktop container's extra capabilities are `SYS_NICE`, `IPC_LOCK`, and `SYS_RESOURCE`. Those raise rtprio, memlock, and nofile for the session. The game process does not hold them. `SYS_ADMIN` is only on the init container.
- The orchestrator can `get`, `list`, `watch`, `create`, `delete`, and `patch` pods in this namespace, and read pod logs. The proxy has no kube token.
