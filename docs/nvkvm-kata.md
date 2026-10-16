# nvkvm-kata on the GPU nodes

This is steps 4 through 6 of [deploy.md](deploy.md). Do that page in order. Do not `kubectl apply` the SunSlop manifests, and do not label the node `nvkvm.kata/ready=true`, until the gate at the bottom of this page prints `GATE_OK`.

The workers already run the NVIDIA driver and the GPU Operator. Keep both. This runtime does not replace them.

nvkvm-kata is a second containerd runtime. Each pod is a QEMU VM whose guest kernel is not the host kernel. The host keeps the NVIDIA driver bound to the card. The guest gets a virtio GPU (`virtio-nvgpu`), not the PCI device. That is the isolation you asked for: a guest kernel, guest `uinput`, and no mount of the host's `/dev/input`.

It is not the GPU Operator's Kata mode. Do not enable `sandboxWorkloads`. That mode unbinds the card onto `vfio-pci`. nvkvm has nothing left to forward if the host driver is gone.

## What this does not give you by default

The upstream README is explicit: nvkvm-kata as published is **compute and headless graphics only**. There is no display broker, no audio broker, and no input broker. `--graphics 1` exists and is marked **unverified** (never built, never booted in their install doc). The virtual display itself lives in [nvkvm-pv](https://github.com/reindertpelsma/nvkvm-pv): one `DRM_MODE_CONNECTOR_VIRTUAL`, one CRTC, one plane, fixed **1920x1080@60**, no guest mode switch. Frames leave that head by capture, not by scanout.

Build with `--graphics 1` anyway, then refuse to schedule pods until the gate at the bottom of this page shows `/dev/dri/card0` inside a guest. If that node is missing, Sunshine has nothing to capture. Do not paper over it with a host `/dev/dri` mount. A desktop product that is not this runtime is [nvkvm-steamos](https://github.com/reindertpelsma/nvkvm-steamos); it is not a Kubernetes RuntimeClass.

"No input" and "no audio" in the kata README mean the VMM does not bridge the host's keyboard or sound card. They do not forbid a guest `uinput` device or a guest PipeWire. Sunshine and Selkies use those, and they never see the host's devices.

## What you must not change in the GPU Operator

Leave the operator in its normal mode: host `nvidia` module, `nvidia.com/gpu` advertised by the device plugin, one full GPU per pod. Do not set:

```
sandboxWorkloads.enabled=true
sandboxWorkloads.mode=kata
sandboxWorkloads.defaultWorkload=vm-passthrough
```

Do not bind the GPUs to `vfio-pci`. Do not install the upstream `kata-deploy` chart's `kata-qemu-nvidia-gpu` class and point these pods at it. That class is VFIO passthrough, one physical GPU per VM, and it takes the card away from every other pod on the node.

The device plugin is how a pod is handed either GPU 0 or GPU 1. The manifest requests `nvidia.com/gpu: 1` and does not pin an index. With time-slicing left at the default of one replica, a two-GPU node admits two of these pods and the scheduler picks the free card.

## Host checks

On the node, as root:

```bash
. /etc/os-release && echo "$ID $VERSION_ID"    # centos 9, or rhel-family
test -e /dev/kvm
mount | awk '$3=="/sys/fs/cgroup"{print $5}'   # cgroup2fs
nvidia-smi -L                                  # the GPUs this node will share
nvidia-ctk --version                           # must be >= 1.14.6
containerd --version
df -BG /var/lib | awk 'NR==2{print $4}'        # need >= 40G free for the build
```

`ID_LIKE` on CentOS Stream 9 contains `rhel`, which is the family the installer supports. SELinux stays enforcing. Their RHEL 9.5 run was enforcing; do not flip the node to permissive to get past an install error. If the shim is denied, read `ausearch -m avc -ts recent` and fix that context.

`nvidia-ctk` has to be a host binary. The operator's toolkit DaemonSet configures containerd, but the installer looks for the binary on the node. If `nvidia-ctk` is missing:

```bash
curl -fsSL https://nvidia.github.io/libnvidia-container/stable/rpm/nvidia-container-toolkit.repo \
  | tee /etc/yum.repos.d/nvidia-container-toolkit.repo
dnf install -y nvidia-container-toolkit
```

Do not run `nvidia-ctk runtime configure` in a way that replaces the operator's containerd snippet. You are only installing the CLI the nvkvm installer uses to discover driver files.

## Install

The installer builds a patched QEMU, a guest kernel, and a guest rootfs, then registers a runtime named `nvkvm-kata`. Kata is pinned at **4.1.0** by the script. There are no prebuilt artifacts. First build is long.

```bash
dnf install -y git
dnf config-manager --set-enabled crb
git clone https://github.com/reindertpelsma/nvkvm-kata
cd nvkvm-kata
# Desktop fragment: uinput, ntsync, squashfs, 32-bit, a dummy sound card, EFI.
# Also defaults memfd_create on. The guest kernel nvkvm builds is >= 6.14.
# --graphics 1 stays required; the fragment does not turn CONFIG_DRM on.
bash /path/to/SunSlop/deploy/kata/apply-desktop-kernel.sh .
sudo scripts/nvkvm-kata-install.sh \
  --install-kata \
  --install-deps \
  --graphics 1 \
  --containerd-cri \
  --no-docker
```

`--no-docker` matters. A kubelet node is not Docker, and the containerd that ships with Docker sets `disabled_plugins = ["cri"]`, which makes a CRI stanza parse and then do nothing.

The script is idempotent. A second run with no changes should change nothing. Useful extras, all documented in their `docs/install.md`:

| Flag | Use |
|---|---|
| `--graphics 1` | Build the guest with the virtual display. Unverified upstream. Required for these pods. |
| `--containerd-cri` | Append the runtime handler to `/etc/containerd/config.toml`. |
| `--no-docker` | Do not touch `/etc/docker/daemon.json`. |
| `--prefix` | Default `/opt/nvkvm-kata`. |
| `--runtime-name` | Default `nvkvm-kata`. The RuntimeClass handler must match. |
| `--force` | Rebuild even if the stamp says the build is current. |

What lands on disk:

| Path | What it is |
|---|---|
| `/opt/qemu-nvkvm/` | nvkvm QEMU |
| `/opt/nvkvm-kata/` | shim, guest kernel, guest rootfs, driver-library bundle |
| `/etc/kata-containers/configuration-nvkvm.toml` | Kata config used only by this runtime |
| `/etc/nvkvm-kata/shim.env` | shim environment, including `NVKVM_QEMU` |
| `/usr/local/bin/containerd-shim-nvkvm-kata-v2` | containerd shim wrapper |
| `/var/lib/nvkvm-kata/` | build tree, backups, install manifest |

Stock `/etc/kata-containers/configuration.toml` is not the file these pods use. Do not point the RuntimeClass at it.

## containerd

`--containerd-cri` appends a block wrapped in `# >>> nvkvm-kata >>>` markers. Check which plugin id this node's containerd actually uses (`containerd --version`; 1.x uses the first, 2.x the second) and that the file matches.

containerd 1.x:

```toml
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.nvkvm-kata]
  runtime_type = "io.containerd.nvkvm-kata.v2"
  privileged_without_host_devices = true
  pod_annotations = ["io.katacontainers.*"]
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.nvkvm-kata.options]
    ConfigPath = "/etc/kata-containers/configuration-nvkvm.toml"
```

containerd 2.x:

```toml
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.nvkvm-kata]
  runtime_type = "io.containerd.nvkvm-kata.v2"
  privileged_without_host_devices = true
  pod_annotations = ["io.katacontainers.*"]
  [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.nvkvm-kata.options]
    ConfigPath = "/etc/kata-containers/configuration-nvkvm.toml"
```

`privileged_without_host_devices = true` is required. Without it, containerd tries to push host device nodes into the guest. The host's `/dev/nvidia*` major numbers are not the guest's, and a host `/dev/input` mount would defeat the reason for using a VM.

Then:

```bash
systemctl restart containerd
systemctl is-active containerd
kubectl get node
```

The GPU Operator rewrites containerd config when the toolkit DaemonSet restarts. After any operator upgrade, confirm the `nvkvm-kata` block is still in the file and that `disabled_plugins` does not contain `cri`. If the operator manages that file from a template, put the same block in the template. A one-off edit will not survive the next toolkit pod.

## RuntimeClass

The installer does not create the Kubernetes object. For the gate, apply this class with no `scheduling` stanza. SunSlop's later apply replaces it and adds `nvkvm.kata/ready=true`. Admission copies that selector onto every pod using the class, and the kubelet rejects the gate pod on an unlabeled node even when `nodeName` is set.

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

Do not label the node yet. The label is the last step, after the gate passes. The handler string has to be the containerd runtime key, which is `nvkvm-kata` unless you changed `--runtime-name`.

## Secure Boot and the TPU

Each seat VM gets both. Kata 4.1 cannot do either by itself.

`firmware` becomes `-bios`. OVMF Secure Boot needs two pflash chips, and `firmware_volume` is only wired up for a TDX guest. There is no annotation for an extra `-device`. The seat pod still asks, and [deploy/kata/gs_kata_shim.py](../deploy/kata/gs_kata_shim.py) is `hypervisor.path`. It rewrites the QEMU argv, then execs the nvkvm shim so the virtio GPU device is unchanged.

On the GPU node:

```bash
dnf install -y edk2-ovmf
install -m 0755 deploy/kata/gs_kata_shim.py /usr/local/bin/gs-kata-shim
python3 /usr/local/bin/gs-kata-shim --self-test
```

In `/etc/kata-containers/configuration-nvkvm.toml`, set `path` to the new shim and append the annotation names the seats use. `default_vcpus` and `default_memory` are already on the pod; they do nothing until they are listed here too.

```toml
[hypervisor.qemu]
path = "/usr/local/bin/gs-kata-shim"
enable_annotations = ["default_vcpus", "default_memory", "firmware", "kernel_params"]
```

Keep every name that was already in `enable_annotations`. Add the shim to `valid_hypervisor_paths` if that list is not empty. `kernel_params` is a trusted annotation: anyone who can create a pod on this RuntimeClass can point the shim at a login directory under `GS_PERSIST_ROOT`. The orchestrator is the only creator. Listing `firmware` without `kernel_params` is the broken case: Kata passes `-bios` and the shim never sees the variable-store path, so it cannot rewrite it.

`/etc/nvkvm-kata/shim.env` (the same file the nvkvm shim already reads):

```
GS_PERSIST_ROOT=/var/lib/gamestream/persistent
GS_UEFI_CODE=/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd
GS_UEFI_TEMPLATE=/usr/share/edk2/ovmf/OVMF_VARS.fd
NVKVM_SHIM=/opt/nvkvm-kata/bin/nvkvm-qemu-shim
```

`GS_PERSIST_ROOT` is the same string as `PERSIST_ROOT`. `GS_UEFI_CODE` and `GS_UEFI_TEMPLATE` are the same strings as `KATA_FIRMWARE` and `KATA_FIRMWARE_VARS`. The template has to be the empty variable store. `OVMF_VARS.secboot.fd` already has keys enrolled, and this guest kernel is not signed, so the VM would not boot. With the empty store the firmware is Secure Boot capable and Secure Boot is off. Enrolling keys writes the per-login store; the next pod for that login keeps them, and then the unsigned kernel will not boot. That file is `<PERSIST_ROOT>/<login>/uefi/OVMF_VARS.fd`. Delete it to start from the template again.

The shim refuses any other path. A `..` component is rejected before it is normalized. If the firmware files are missing, or the variable store cannot be created, `-bios` is removed and the seat falls back to Kata's direct kernel boot instead of hanging on a half-configured OVMF. `KATA_SECURE_BOOT=false` does not ask.

The TPU is a 1 MiB int8 scratchpad on a virtio serial port, not a Cloud TPU and not `libtpu`. QEMU has no TPU model, and neither does nvkvm. The device in the guest is `/dev/virtio-ports/org.sunslop.tpu` (`GS_TPU_DEVICE`). The scratchpad file is `<PERSIST_ROOT>/<login>/<TPU_STATE_DIR>/state.bin`, which the seat sees at `GS_TPU_STATE` because the home mount is that login's directory. The socket stays on the host under `/run/gs-tpu/`. Deleting the pod does not delete the file. `TPU_EMULATION=false` does not ask.

The port speaks four lines. Offsets are bytes.

| Line | Effect |
|---|---|
| `STAT` | `OK 1048576` |
| `READ <off> <len>` | up to 4096 bytes after the `OK <len>` line |
| `WRITE <off> <len>` and then that many bytes | stored, then `fsync` |
| `DOT <a> <b> <n> <dst>` | int8 dot product, int32 little-endian result stored at `dst` |

`DOT` with `n` past either vector, or a `WRITE` past the end, returns `ERR range` and does not extend the file.

The gate pod below does not carry these annotations, so it does not prove this section. After a real seat is up: `ls /sys/firmware/efi` (Secure Boot firmware ran) and `ls /dev/virtio-ports/org.sunslop.tpu`. A seat that never becomes Ready after this change is the OVMF path; set `KATA_SECURE_BOOT=false` and leave the TPU on. `nosmm` is stripped and `smm=on` is added only when the pflash path is actually used. OVMF Secure Boot needs SMM.

## Prove the runtime before you label the node

A CUDA image is enough to prove the driver. It is not enough to prove the display. Run both checks inside a guest, on this node.

```bash
# NAMESPACE from deploy/gs-config.yaml. NODE is the worker you are proving.
NS=gamestream
NODE=gpu-node-1
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: nvkvm-gate
  namespace: ${NS}
spec:
  runtimeClassName: nvkvm-kata
  restartPolicy: Never
  nodeName: ${NODE}
  containers:
    - name: gate
      image: nvidia/cuda:13.3.1-cudnn-devel-ubuntu26.04
      command: ["bash", "-lc"]
      args:
        - |
          set -u
          echo "KERNEL \$(uname -r)"
          nvidia-smi -L
          echo "DRI \$(ls -1 /dev/dri 2>/dev/null || echo NONE)"
          echo "NVIDIA0 \$(ls -l /dev/nvidia0 2>/dev/null || echo NONE)"
          echo "FS \$(grep -E 'squashfs|overlay|fuse' /proc/filesystems | tr '\n' ' ')"
          echo "NTSYNC \$(grep ntsync /proc/misc || echo NONE)"
          echo "UINPUT \$(awk '\$2==\"uinput\"{print}' /proc/misc || echo NONE)"
          echo "SND \$(grep -i dummy /proc/asound/cards 2>/dev/null || echo NONE)"
          if [[ -r /proc/config.gz ]]; then
            gzip -dc /proc/config.gz | grep -E \\
              '^CONFIG_(INPUT_UINPUT|INPUT_MISC|INPUT_EVDEV|NTSYNC|FUSE_FS|FUSE_PASSTHROUGH|OVERLAY_FS|SQUASHFS|IA32_EMULATION|SND_DUMMY|SND_SEQUENCER|USER_NS|DRM|EFI|MEMFD_CREATE|IKCONFIG_PROC)='
          else
            echo "NO_PROC_CONFIG"
          fi
          test -e /dev/nvidia0
          test -e /dev/dri/card0
          grep -q squashfs /proc/filesystems
          grep -q overlay /proc/filesystems
          grep -q fuse /proc/filesystems
          awk '\$2=="uinput"{found=1} END{exit !found}' /proc/misc
          grep -q ntsync /proc/misc
          grep -qi dummy /proc/asound/cards
          echo GATE_OK
      resources:
        limits:
          nvidia.com/gpu: "1"
          memory: 4Gi
EOF
kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded pod/nvkvm-gate --timeout=300s
kubectl -n "$NS" logs pod/nvkvm-gate
```

The class above has no node selector, so this pod can run before the label exists. If SunSlop has already been applied, the class has `nvkvm.kata/ready=true` and the kubelet will reject this pod. Put the no-selector class back, run the gate, label the node, then apply SunSlop again.

Required before any streaming pod:

| Check | Pass | Fail means |
|---|---|---|
| `uname -r` ends in something other than the host kernel | guest kernel booted | the pod ran on runc, or the RuntimeClass handler is wrong |
| `nvidia-smi -L` lists one GPU | driver libraries were injected and the virtio GPU attached | CDI discover failed, or the operator took the card onto vfio |
| `/dev/dri/card0` exists | `--graphics 1` actually built a display | streaming cannot work on this build. Stop. |
| `uinput` in `/proc/misc` | the desktop fragment was merged; Sunshine can create a gamepad | the guest is still the compute kernel. Re-run `apply-desktop-kernel.sh` and rebuild. Do not mount host `uinput`. The node is misc major 10, not its own line in `/proc/devices`. |
| `ntsync` in `/proc/misc` | Proton can use `/dev/ntsync` | kernel is older than 6.14, or `CONFIG_NTSYNC` did not land |
| `squashfs`, `overlay`, and `fuse` in `/proc/filesystems` | Steam Linux Runtime can mount its images | fragment was not in the build |
| `dummy` in `/proc/asound/cards` | PipeWire and Proton have a sound card with no host DAC | `CONFIG_SND_DUMMY` did not land |

`GATE_OK` is the only line that counts. `NVIDIA0 NONE` with a working `nvidia-smi` can still be fine, because nvkvm's device nodes are created by the guest module and are not the host's `/dev/nvidia0`. A missing `/dev/dri/card0` is not fine. `NO_PROC_CONFIG` means `CONFIG_IKCONFIG_PROC` did not land; the `/proc` checks above are still required. `/sys/firmware/efi` is not on this gate pod. The gate does not carry the seat firmware annotation, so it is direct-kernel boot even when `CONFIG_EFI=y`. A real seat with Secure Boot enabled is the EFI check.

Also confirm the host card never moved:

```bash
nvidia-smi -L
ls /sys/bus/pci/drivers/nvidia/
```

Both GPUs still belong to `nvidia`, not `vfio-pci`.

Optional, from inside a later Fedora guest once the image exists: `vulkaninfo --summary` must name an NVIDIA device, and `ffmpeg -hide_banner -f lavfi -i nullsrc=s=256x256:d=1 -c:v h264_nvenc -f null -` must encode. Those prove NVENC, which the CUDA gate does not.

## Only then

```bash
NODE=gpu-node-1
kubectl label node "$NODE" nvkvm.kata/ready=true
```

Repeat the install and the gate on the next node. Then continue at step 8 of [deploy.md](deploy.md). The proxy will not start on this node until the label is present.

## After a driver upgrade

The shim refuses to start a container when `/proc/driver/nvidia/version` no longer matches the bundle it discovered. On the next NVIDIA upgrade, re-run discover from the nvkvm-kata checkout:

```bash
# from the nvkvm-kata checkout, the discover tool the installer put on the path
nvkvm-kata-gpu-cdi discover --force
```

Reboot if the new driver was installed but the loaded module is still the old one. Re-run the gate. Do not skip it because the previous label is still on the node.

## Uninstall

From the checkout:

```bash
sudo scripts/nvkvm-kata-uninstall.sh
```

`--purge` drops the build tree. `--remove-qemu` and `--remove-kata` also remove those prefixes. Remove the RuntimeClass and the node label yourself. Uninstall does not touch the GPU Operator.
