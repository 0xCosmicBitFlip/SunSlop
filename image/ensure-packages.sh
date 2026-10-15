#!/bin/bash
# Make the shared layer match the startup package list.
# Already-installed names are left alone. Names this script installed before,
# and that are no longer on the list, are removed. Never dnf-update.
# Per-user packages are not applied here; those belong under the home directory.
set -euo pipefail

home="${GS_HOME:-/home/${GS_USER:-gsuser}}"
if [[ -f "${home}/packages.list" ]]; then
  echo "ensure-packages: ignoring ${home}/packages.list; the startup list is shared"
fi

list="${GS_PACKAGES_LIST:-/etc/gamestream/packages.list}"
manifest="${GS_LAYER_MANIFEST:-/var/lib/gs-layer/installed.list}"
cachedir="${GS_DNF_CACHEDIR:-/var/cache/dnf}"
install -d "$cachedir" "$(dirname "$manifest")"
[[ -f "$list" ]] || : > "$list"
[[ -f "$manifest" ]] || : > "$manifest"

read_names() {
  local file="$1"
  local -n dest="$2"
  local pkg
  declare -A seen=()
  dest=()
  [[ -f "$file" ]] || return 0
  while IFS= read -r pkg || [[ -n "$pkg" ]]; do
    [[ "$pkg" =~ ^[[:alnum:]_.+-]+$ ]] || continue
    [[ -n "${seen[$pkg]:-}" ]] && continue
    seen["$pkg"]=1
    dest+=("$pkg")
  done < "$file"
}

read_names "$list" desired
read_names "$manifest" previous

declare -A want=()
for pkg in "${desired[@]+"${desired[@]}"}"; do
  want["$pkg"]=1
done

remove=()
for pkg in "${previous[@]+"${previous[@]}"}"; do
  if [[ -z "${want[$pkg]:-}" ]] && rpm -q "$pkg" >/dev/null 2>&1; then
    remove+=("$pkg")
  fi
done
if ((${#remove[@]})); then
  echo "ensure-packages: removing ${remove[*]}"
  dnf remove -y --setopt=cachedir="$cachedir" "${remove[@]}"
fi

missing=()
for pkg in "${desired[@]+"${desired[@]}"}"; do
  rpm -q "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
done

need_fusion=0
for pkg in "${missing[@]+"${missing[@]}"}"; do
  [[ "$pkg" == "steam" ]] && need_fusion=1
done
if ((need_fusion)) && ! rpm -q rpmfusion-nonfree-release >/dev/null 2>&1; then
  rel="$(rpm -E %fedora)"
  dnf -y --setopt=cachedir="$cachedir" install \
    "https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-${rel}.noarch.rpm" \
    "https://mirrors.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-${rel}.noarch.rpm"
fi

if ((${#missing[@]})); then
  echo "ensure-packages: installing ${missing[*]}"
  dnf install -y --setopt=cachedir="$cachedir" "${missing[@]}"
fi

{
  for pkg in "${desired[@]+"${desired[@]}"}"; do
    if rpm -q "$pkg" >/dev/null 2>&1; then
      printf '%s\n' "$pkg"
    fi
  done
} > "$manifest"
echo "ensure-packages: startup set matches"
