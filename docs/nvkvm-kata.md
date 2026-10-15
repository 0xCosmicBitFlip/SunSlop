# nvkvm-kata on the GPU nodes

Do this on every CentOS Stream 9 worker before `python3 deploy/render.py | kubectl apply -f -`. Seats are not applied by hand. The orchestrator creates one when a client connects, and it will not schedule until this node is labeled `nvkvm.kata/ready=true`.

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

The installer does not create the Kubernetes object. Apply this once per cluster:

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
scheduling:
  nodeSelector:
    nvkvm.kata/ready: "true"
```

Do not label the node yet. The label is the last step, after the gate passes. The handler string has to be the containerd runtime key, which is `nvkvm-kata` unless you changed `--runtime-name`.

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
          if [[ -r /proc/config.gz ]]; then
            gzip -dc /proc/config.gz | grep -E \\
              'CONFIG_(INPUT_UINPUT|USER_NS|DRM)='
          else
            echo "NO_PROC_CONFIG"
          fi
          test -e /dev/nvidia0
          test -e /dev/dri/card0
          echo GATE_OK
      resources:
        limits:
          nvidia.com/gpu: "1"
          memory: 4Gi
EOF
kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded pod/nvkvm-gate --timeout=300s
kubectl -n "$NS" logs pod/nvkvm-gate
```

The RuntimeClass above has a node selector, so this pod will not schedule until you either label the node or delete the `scheduling` block for the duration of the test. Easiest path: apply the RuntimeClass **without** the `scheduling` stanza, run the gate, then add the stanza and the label.

Required before any streaming pod:

| Check | Pass | Fail means |
|---|---|---|
| `uname -r` ends in something other than the host kernel | guest kernel booted | the pod ran on runc, or the RuntimeClass handler is wrong |
| `nvidia-smi -L` lists one GPU | driver libraries were injected and the virtio GPU attached | CDI discover failed, or the operator took the card onto vfio |
| `/dev/dri/card0` exists | `--graphics 1` actually built a display | streaming cannot work on this build. Stop. |
| `CONFIG_INPUT_UINPUT=y` or `=m` | Sunshine can create a gamepad inside the guest | do not mount host `uinput` to compensate |

`GATE_OK` is the only line that counts. `NVIDIA0 NONE` with a working `nvidia-smi` can still be fine, because nvkvm's device nodes are created by the guest module and are not the host's `/dev/nvidia0`. A missing `/dev/dri/card0` is not fine.

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

Repeat the install and the gate on the second node. Then follow [the deploy guide](../README.md).

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
