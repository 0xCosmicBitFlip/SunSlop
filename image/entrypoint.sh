#!/bin/bash
# Desktop container. Root here is not allowed to change the shared layer.
# The init container (layer-init) has already installed packages and built
# this pod's /etc. /usr and /opt are read-only mounts. /games and /gamessd
# are mounted read-write only for a common login. A unique login does not
# have them; installs go in the home directory.
# Other writable state is the login's home, plus the tmpfs mounts the pod
# spec adds (/tmp, /var/tmp, /var/log, /var/cache, /run).
set -euo pipefail

user="${GS_USER:-gsuser}"
uid="${GS_UID:-1000}"
gid="${GS_GID:-1000}"
home="${GS_HOME:-/home/${user}}"
runtime="${XDG_RUNTIME_DIR:-/run/user/${uid}}"
wayland="${WAYLAND_DISPLAY:-wayland-0}"
layer="${GS_LAYER:-/gs-layer}"
games="${GS_GAMES:-}"
gamessd="${GS_GAMESSD:-}"
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
case "${home}${runtime}${layer}${games}${gamessd}${config_rel}" in
  *[!a-zA-Z0-9_./-]*)
    echo "seat path has an unsafe character" >&2
    exit 1
    ;;
esac

refuse_writable() {
  local path="$1"
  if touch "${path}/.sunslop-write-test" 2>/dev/null; then
    rm -f "${path}/.sunslop-write-test"
    echo "seat: ${path} is writable. The desktop container must not be able to change a shared tree, even as root." >&2
    exit 1
  fi
}

if mountpoint -q "$layer" 2>/dev/null; then
  echo "seat: ${layer} is mounted in the desktop container. Only the init container may see the layer." >&2
  exit 1
fi
if [[ "${GS_LAYER_ALLOW_UNMOUNTED:-}" != 1 ]]; then
  refuse_writable /usr
  if [[ -d /opt ]]; then
    refuse_writable /opt
  fi
fi

if [[ ! -e /dev/uinput ]]; then
  modprobe uinput 2>/dev/null || true
fi
for mod in ntsync snd-dummy fuse; do
  modprobe "$mod" 2>/dev/null || true
done
# No devtmpfs mount: that needs CAP_SYS_ADMIN, which this container does not
# have. The drivers are built-in. mknod needs CAP_MKNOD, which is in the
# default set. uinput, ntsync, fuse, and uhid are misc major 10.
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
# Inherited by supervisord and then by the desktop user. Raising the hard
# limit is why the pod has SYS_RESOURCE, SYS_NICE, and IPC_LOCK. The game
# process does not need those capabilities itself.
ulimit -n 524288 || true
ulimit -l unlimited || true
ulimit -r 99 || true
ulimit -e 40 || true

if ! ldconfig -p 2>/dev/null | grep -q 'libGLX_nvidia'; then
  echo "nvkvm: libGLX_nvidia is not on the loader path. Steam needs the host NVIDIA userspace (graphics, display, video), including the 32-bit libraries nvkvm-steam stages." >&2
fi
if [[ ! -e /dev/dri/card0 ]]; then
  echo "nvkvm: /dev/dri/card0 is missing. Rebuild the guest with --graphics 1 and boot with -vga none so the virtio-nvgpu DRM node is the display." >&2
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
  echo "desktop-kernel: missing${missing} (rebuild the nvkvm guest with deploy/kata/desktop.x86_64.conf, kernel >= 6.14, --graphics 1)" >&2
else
  echo "desktop-kernel: uinput ntsync squashfs overlay fuse snd-dummy"
fi

install -d -o root -g root -m 0755 /run /var/log /tmp /var/tmp
install -d -m 0700 "${runtime}" "${home}"

# /etc is this pod's copy. Creating the account here does not touch the layer.
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

install -d -o "$user" -g "$user" "${home}/.config/labwc" "${home}/${config_rel}" "${home}/.cache"
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

tpl=/etc/gamestream/supervisord.conf.in
if [[ ! -f "$tpl" && -f /etc/supervisord.conf ]]; then
  tpl=/etc/supervisord.conf
fi
if [[ ! -f "$tpl" ]]; then
  echo "seat: missing supervisord template" >&2
  exit 1
fi

export GS_USER="$user" GS_HOME="$home"
sed \
  -e "s#@GS_USER@#${user}#g" \
  -e "s#@GS_HOME@#${home}#g" \
  -e "s#@XDG_RUNTIME_DIR@#${runtime}#g" \
  -e "s#@WAYLAND_DISPLAY@#${wayland}#g" \
  -e "s#@SELKIES_ENCODER@#${encoder}#g" \
  -e "s#@SELKIES_PORT@#${selkies_port}#g" \
  -e "s#@SELKIES_ADDR@#${selkies_addr}#g" \
  -e "s#@XDG_CONFIG_HOME@#${xdg_config}#g" \
  "$tpl" > /run/gs-supervisord.conf
if grep -q '@[A-Z_]*@' /run/gs-supervisord.conf; then
  echo "supervisord template still has placeholders" >&2
  exit 1
fi

exec /usr/bin/supervisord -c /run/gs-supervisord.conf
