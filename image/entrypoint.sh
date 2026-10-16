#!/bin/bash
# Root in the guest. The desktop session runs as GS_USER (uid GS_UID).
# Those values, the home, and the layer mount come from the seat env, which
# the orchestrator copies out of the gs-config ConfigMap.
#
# Extra RPMs persist in the shared layer directory, not in a home.
# The CRI-O root is CephFS through FUSE, and kata shows that to the guest as
# virtio-fs. Kernel overlay cannot use either as an upper directory, so the
# layer is a real directory of files and this script bind-mounts it. CephFS
# flock keeps two seats from seeding or running dnf at the same time.
# Personal installs belong under the home directory, not in this tree.
set -euo pipefail

user="${GS_USER:-gsuser}"
uid="${GS_UID:-1000}"
gid="${GS_GID:-1000}"
home="${GS_HOME:-/home/${user}}"
runtime="${XDG_RUNTIME_DIR:-/run/user/${uid}}"
wayland="${WAYLAND_DISPLAY:-wayland-0}"
layer="${GS_LAYER:-/gs-layer}"
encoder="${SELKIES_ENCODER:-nvh264enc}"
selkies_port="${SELKIES_PORT:-8082}"
selkies_addr="${SELKIES_ADDR:-0.0.0.0}"
config_rel="${SUNSHINE_CONFIG_REL:-.config/sunshine}"

case "${user}${uid}${gid}${wayland}${encoder}${selkies_port}${selkies_addr}" in
  *[!a-zA-Z0-9_.:-]*)
    echo "seat identity has an unsafe character" >&2
    exit 1
    ;;
esac
case "${home}${runtime}${layer}${config_rel}" in
  *[!a-zA-Z0-9_./-]*)
    echo "seat path has an unsafe character" >&2
    exit 1
    ;;
esac

install -d -o root -g root -m 0755 /run /var/log
install -d -m 0700 "${runtime}" "${home}"

if [[ ! -e /dev/uinput ]]; then
  modprobe uinput 2>/dev/null || true
fi
# The kata rootfs has no /lib/modules for this kernel. =y drivers register
# themselves; modprobe is only here for an older =m build.
for mod in ntsync snd-dummy fuse; do
  modprobe "$mod" 2>/dev/null || true
done
if ! mountpoint -q /run/gs-dev; then
  install -d /run/gs-dev
  mount -t devtmpfs devtmpfs /run/gs-dev 2>/dev/null || true
fi
if mountpoint -q /run/gs-dev; then
  for node in fuse ntsync uinput uhid; do
    if [[ -e "/run/gs-dev/$node" && ! -e "/dev/$node" ]]; then
      touch "/dev/$node"
      if ! mount --bind "/run/gs-dev/$node" "/dev/$node"; then
        rm -f "/dev/$node"
      fi
    fi
  done
  if [[ -d /run/gs-dev/snd ]]; then
    install -d /dev/snd
    if ! mountpoint -q /dev/snd; then
      mount --bind /run/gs-dev/snd /dev/snd || true
    fi
  fi
  if [[ -d /run/gs-dev/dri && ! -e /dev/dri/card0 ]]; then
    install -d /dev/dri
    mount --bind /run/gs-dev/dri /dev/dri || true
  fi
fi
# uinput, ntsync, fuse, and uhid are misc devices (major 10). They show up
# in /proc/misc, not as their own line in /proc/devices. devtmpfs already
# created the node when the driver is built-in; mknod is the fallback.
mknod_misc() {
  local name="$1" mode="$2" minor
  if [[ -e "/dev/$name" ]]; then
    return 0
  fi
  minor="$(awk -v n="$name" '$2==n {print $1; exit}' /proc/misc || true)"
  if [[ -z "$minor" ]]; then
    return 0
  fi
  mknod -m "$mode" "/dev/$name" c 10 "$minor"
}
mknod_misc fuse 0666 || true
mknod_misc ntsync 0666 || true
mknod_misc uinput 0660 || true
mknod_misc uhid 0666 || true
if [[ -e /dev/ntsync ]]; then
  chmod 0666 /dev/ntsync || true
fi
if [[ -e /dev/fuse ]]; then
  chmod 0666 /dev/fuse || true
fi
if [[ -e /dev/uinput ]]; then
  group="$(getent group input | cut -d: -f1 || true)"
  if [[ -n "${group}" ]]; then
    chgrp "${group}" /dev/uinput || true
  fi
  chmod 0660 /dev/uinput || true
fi
if [[ -e /dev/uhid ]]; then
  chmod 0666 /dev/uhid || true
fi
if [[ -d /dev/snd ]]; then
  chmod 0755 /dev/snd || true
  find /dev/snd -type c -exec chmod 0666 {} + || true
fi
# No udev in this seat. devtmpfs nodes are root:root 0600 until chmod.
# Proton maps far more VMAs than the default 65530, and Steam watches
# a lot of files. The limits are inherited by supervisord.
sysctl -w vm.max_map_count=1048576 >/dev/null 2>&1 || true
sysctl -w fs.inotify.max_user_watches=1048576 >/dev/null 2>&1 || true
sysctl -w fs.inotify.max_user_instances=1024 >/dev/null 2>&1 || true
ulimit -n 524288 || true
ulimit -l unlimited || true
if ! mountpoint -q /dev/shm; then
  install -d -m 1777 /dev/shm
  mount -t tmpfs -o mode=1777,nosuid,nodev,size=50% shm /dev/shm || true
fi
if grep -qw binfmt_misc /proc/filesystems && ! mountpoint -q /proc/sys/fs/binfmt_misc; then
  install -d /proc/sys/fs/binfmt_misc
  mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc || true
fi
missing=""
awk '$2=="uinput"{found=1} END{exit !found}' /proc/misc || missing="${missing} uinput"
grep -q ntsync /proc/misc || missing="${missing} ntsync"
grep -qw squashfs /proc/filesystems || missing="${missing} squashfs"
grep -qw overlay /proc/filesystems || missing="${missing} overlay"
grep -qw fuse /proc/filesystems || missing="${missing} fuse"
grep -qi dummy /proc/asound/cards 2>/dev/null || missing="${missing} snd-dummy"
[[ -e /dev/uinput ]] || missing="${missing} /dev/uinput"
[[ -e /dev/ntsync ]] || missing="${missing} /dev/ntsync"
[[ -e /dev/fuse ]] || missing="${missing} /dev/fuse"
if [[ -n "${missing}" ]]; then
  echo "desktop-kernel: missing${missing} (rebuild the nvkvm guest with deploy/kata/desktop.x86_64.conf, kernel >= 6.14)" >&2
else
  echo "desktop-kernel: uinput ntsync squashfs overlay fuse snd-dummy"
fi

case "$layer" in
  /usr|/usr/*|/etc|/etc/*)
    echo "layer: ${layer} must not live inside /usr or /etc" >&2
    exit 1
    ;;
esac
if [[ "${GS_LAYER_ALLOW_UNMOUNTED:-}" != 1 ]] && ! mountpoint -q "$layer"; then
  echo "layer: ${layer} is not a mount, so the shared layer would vanish with the pod" >&2
  exit 1
fi

install -d "$layer" "$layer/dnf-cache"
snap="$(mktemp -d /tmp/gs-pod.XXXXXX)"
for f in resolv.conf hosts hostname machine-id; do
  if [[ -e "/etc/$f" ]]; then
    cp -L "/etc/$f" "$snap/$f" 2>/dev/null || cp -a "/etc/$f" "$snap/$f" || true
  fi
done
tpl=/etc/gamestream/supervisord.conf.in
if [[ ! -f "$tpl" && -f /etc/supervisord.conf ]]; then
  tpl=/etc/supervisord.conf
fi
if [[ ! -f "$tpl" ]]; then
  echo "layer: missing supervisord template" >&2
  exit 1
fi
cp -a "$tpl" /tmp/gs-supervisord.in
if [[ -f "${layer}/packages.list" ]]; then
  cp -a "${layer}/packages.list" /tmp/gs-packages.list
elif [[ -f /etc/gamestream/packages.list ]]; then
  cp -a /etc/gamestream/packages.list /tmp/gs-packages.list
else
  : > /tmp/gs-packages.list
fi

image_id="$(rpm -qa --qf '%{NEVRA}\n' | sort | sha256sum | awk '{print $1}')"
exec 9>"$layer/lock"
if ! flock 9; then
  echo "layer: flock ${layer}/lock failed" >&2
  exit 1
fi

if [[ ! -f "$layer/image-id" || "$(cat "$layer/image-id")" != "$image_id" ]]; then
  echo "layer: seeding /usr and /etc from this image into ${layer}"
  rm -rf "$layer/usr" "$layer/etc" "$layer/installed.list"
  mkdir -p "$layer/usr" "$layer/etc"
  cp -a /usr/. "$layer/usr/"
  cp -a /etc/. "$layer/etc/"
  printf '%s\n' "$image_id" > "$layer/image-id"
  : > "$layer/installed.list"
  echo "layer: seed done"
fi

mount --bind "$layer/usr" /usr
mount --bind "$layer/etc" /etc
for f in resolv.conf hosts hostname machine-id; do
  if [[ -f "$snap/$f" ]]; then
    if [[ -L "/etc/$f" ]]; then
      rm -f "/etc/$f"
      touch "/etc/$f"
    fi
    mount --bind "$snap/$f" "/etc/$f"
  fi
done
echo "layer: bound ${layer}"

# /etc is the shared layer after the bind, so the unix account is shared too.
# Every seat uses the same GS_USER. Create it here if this image did not.
if ! getent group "$gid" >/dev/null && ! getent group "$user" >/dev/null; then
  groupadd -g "$gid" "$user"
elif ! getent group "$user" >/dev/null; then
  gname="$(getent group "$gid" | cut -d: -f1)"
  groupmod -n "$user" "$gname"
fi
if getent passwd "$user" >/dev/null; then
  usermod -u "$uid" -g "$gid" -d "$home" "$user"
elif getent passwd "$uid" >/dev/null; then
  old="$(getent passwd "$uid" | cut -d: -f1)"
  usermod -l "$user" -d "$home" "$old"
  usermod -u "$uid" -g "$gid" "$user"
else
  useradd -u "$uid" -g "$gid" -d "$home" -M -s /bin/bash "$user"
fi
for g in render video input audio; do
  getent group "$g" >/dev/null && usermod -aG "$g" "$user" || true
done
chown "${user}:${user}" "$runtime" "$home"

install -d -o "$user" -g "$user" "${home}/.config/labwc" "${home}/${config_rel}"
if [[ ! -e ${home}/.config/labwc/autostart ]]; then
  install -o "$user" -g "$user" -m 0644 /etc/gamestream/labwc-autostart \
    "${home}/.config/labwc/autostart"
fi
conf="${home}/${config_rel}/sunshine.conf"
if [[ ! -e "$conf" ]]; then
  install -o "$user" -g "$user" -m 0644 /etc/gamestream/sunshine.conf "$conf"
fi
export SUNSHINE_BASE_PORT="${SUNSHINE_BASE_PORT:-47989}"
export SUNSHINE_STATE_FILE="${SUNSHINE_STATE_FILE:-sunshine_state.json}"
export GS_PROXY_CLIENT_NAME="${GS_PROXY_CLIENT_NAME:-gs-proxy}"
state="${home}/${config_rel}/${SUNSHINE_STATE_FILE}"
python3 /usr/local/bin/seat-boot.py --conf "$conf" --state "$state"
chown "${user}:${user}" "$conf" "$state" || true
chown -R "${user}:${user}" "${home}/${config_rel}" || true

# Sunshine's appdata is ${XDG_CONFIG_HOME}/sunshine, not the process cwd.
case "${config_rel}" in
  */sunshine)
    xdg_config="${home}/${config_rel%/sunshine}"
    xdg_config="${xdg_config%/}"
    ;;
  sunshine)
    xdg_config="${home}"
    ;;
  *)
    xdg_config="${home}/.config"
    ;;
esac

export GS_USER="$user" GS_HOME="$home"
export GS_DNF_CACHEDIR="$layer/dnf-cache"
export GS_LAYER_MANIFEST="$layer/installed.list"
export GS_PACKAGES_LIST=/tmp/gs-packages.list
/usr/local/bin/ensure-packages.sh
flock -u 9

sed \
  -e "s#@GS_USER@#${user}#g" \
  -e "s#@GS_HOME@#${home}#g" \
  -e "s#@XDG_RUNTIME_DIR@#${runtime}#g" \
  -e "s#@WAYLAND_DISPLAY@#${wayland}#g" \
  -e "s#@SELKIES_ENCODER@#${encoder}#g" \
  -e "s#@SELKIES_PORT@#${selkies_port}#g" \
  -e "s#@SELKIES_ADDR@#${selkies_addr}#g" \
  -e "s#@XDG_CONFIG_HOME@#${xdg_config}#g" \
  /tmp/gs-supervisord.in > /run/gs-supervisord.conf
if grep -q '@[A-Z_]*@' /run/gs-supervisord.conf; then
  echo "supervisord template still has placeholders" >&2
  exit 1
fi

exec /usr/bin/supervisord -c /run/gs-supervisord.conf
