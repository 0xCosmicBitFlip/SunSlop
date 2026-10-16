#!/bin/bash
# Init container. The only process that may write the shared package layer.
# It installs and removes RPMs, then copies /etc into a per-pod directory.
# The desktop container mounts /usr and /opt read-only and never sees this
# directory. A seat that is already running is not updated until it is
# recreated; the flock only serialises two inits.
set -euo pipefail

prepare_private_etc() {
  local layer="$1" dest="$2" snap="$3" id f
  rm -rf "$dest/etc"
  mkdir -p "$dest"
  cp -a "$layer/etc" "$dest/etc"
  if command -v dbus-uuidgen >/dev/null 2>&1; then
    id="$(dbus-uuidgen)"
  else
    id="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  fi
  printf '%s\n' "$id" > "$dest/etc/machine-id"
  for f in resolv.conf hosts hostname; do
    if [[ -f "$snap/$f" ]]; then
      rm -f "$dest/etc/$f"
      cp -a "$snap/$f" "$dest/etc/$f"
    fi
  done
}

if [[ "${1:-}" == "--self-test" ]]; then
  root="$(mktemp -d)"
  layer="$root/layer"
  dest="$root/pod"
  snap="$root/snap"
  mkdir -p "$layer/etc" "$layer/usr" "$snap"
  printf 'shared\n' > "$layer/etc/secret"
  printf '10.0.0.1\n' > "$snap/resolv.conf"
  printf 'old-machine\n' > "$layer/etc/machine-id"
  prepare_private_etc "$layer" "$dest" "$snap"
  printf 'pwned\n' > "$dest/etc/secret"
  test "$(cat "$layer/etc/secret")" = "shared"
  test "$(cat "$dest/etc/secret")" = "pwned"
  test "$(cat "$dest/etc/resolv.conf")" = "10.0.0.1"
  test "$(cat "$dest/etc/machine-id")" != "old-machine"
  test -n "$(cat "$dest/etc/machine-id")"
  echo "layer-init self-test ok"
  exit 0
fi

user="${GS_USER:-gsuser}"
uid="${GS_UID:-1000}"
gid="${GS_GID:-1000}"
home="${GS_HOME:-/home/${user}}"
layer="${GS_LAYER:-/gs-layer}"

case "${user}${uid}${gid}" in
  *[!a-zA-Z0-9_.:-]*)
    echo "layer: seat identity has an unsafe character" >&2
    exit 1
    ;;
esac
case "${home}${layer}" in
  *[!a-zA-Z0-9_./-]*)
    echo "layer: seat path has an unsafe character" >&2
    exit 1
    ;;
esac
case "$layer" in
  /usr|/usr/*|/etc|/etc/*|/opt|/opt/*)
    echo "layer: ${layer} must not live inside /usr, /etc, or /opt" >&2
    exit 1
    ;;
esac
if [[ "${GS_LAYER_ALLOW_UNMOUNTED:-}" != 1 ]] && ! mountpoint -q "$layer"; then
  echo "layer: ${layer} is not a mount, so the shared layer would vanish with the pod" >&2
  exit 1
fi

snap="$(mktemp -d /tmp/gs-pod.XXXXXX)"
for f in resolv.conf hosts hostname; do
  if [[ -e "/etc/$f" ]]; then
    cp -L "/etc/$f" "$snap/$f" 2>/dev/null || cp -a "/etc/$f" "$snap/$f" || true
  fi
done

sysctl -w vm.max_map_count=1048576 >/dev/null
sysctl -w fs.inotify.max_user_watches=1048576 >/dev/null
sysctl -w fs.inotify.max_user_instances=1024 >/dev/null
if [[ -e /proc/sys/kernel/unprivileged_userns_clone ]]; then
  sysctl -w kernel.unprivileged_userns_clone=1 >/dev/null || true
fi

install -d "$layer" "$layer/dnf-cache" "$layer/usr" "$layer/etc" "$layer/opt"
image_id="$(
  {
    rpm -qa --qf '%{NEVRA}\n' | sort
    sha256sum \
      /usr/local/bin/layer-init \
      /usr/local/bin/gamestream-entrypoint \
      /usr/local/bin/ensure-packages.sh \
      /usr/local/bin/seat-boot.py \
      /etc/gamestream/packages.list
  } | sha256sum | awk '{print $1}'
)"

exec 9>"$layer/lock"
if ! flock 9; then
  echo "layer: flock ${layer}/lock failed" >&2
  exit 1
fi

if [[ ! -f "$layer/image-id" || "$(cat "$layer/image-id")" != "$image_id" ]]; then
  echo "layer: seeding /usr /etc /opt from this image into ${layer}"
  rm -rf "$layer/usr" "$layer/etc" "$layer/opt" "$layer/installed.list"
  mkdir -p "$layer/usr" "$layer/etc" "$layer/opt"
  cp -a /usr/. "$layer/usr/"
  cp -a /etc/. "$layer/etc/"
  if [[ -d /opt ]]; then
    cp -a /opt/. "$layer/opt/"
  fi
  printf '%s\n' "$image_id" > "$layer/image-id"
  : > "$layer/installed.list"
  echo "layer: seed done"
fi

mount --bind "$layer/usr" /usr
mount --bind "$layer/etc" /etc
if [[ -d "$layer/opt" ]]; then
  mount --bind "$layer/opt" /opt
fi
for f in resolv.conf hosts hostname; do
  if [[ -f "$snap/$f" ]]; then
    if [[ -L "/etc/$f" ]]; then
      rm -f "/etc/$f"
      touch "/etc/$f"
    fi
    mount --bind "$snap/$f" "/etc/$f"
  fi
done

if [[ -f "${layer}/packages.list" ]]; then
  cp -a "${layer}/packages.list" /tmp/gs-packages.list
elif [[ -f /etc/gamestream/packages.list ]]; then
  cp -a /etc/gamestream/packages.list /tmp/gs-packages.list
else
  : > /tmp/gs-packages.list
fi
export GS_DNF_CACHEDIR="$layer/dnf-cache"
export GS_LAYER_MANIFEST="$layer/installed.list"
export GS_PACKAGES_LIST=/tmp/gs-packages.list
export GS_HOME="$home" GS_USER="$user"
/usr/local/bin/ensure-packages.sh

# Drop the binds so the copy reads the layer files, not a mount of themselves.
umount /etc || true
umount /opt || true
umount /usr || true
if [[ ! -d /pod-etc ]]; then
  echo "layer: /pod-etc is not mounted; the desktop would share /etc" >&2
  exit 1
fi
prepare_private_etc "$layer" /pod-etc "$snap"
echo "layer: private /etc ready; shared tree left for the desktop read-only"
flock -u 9
