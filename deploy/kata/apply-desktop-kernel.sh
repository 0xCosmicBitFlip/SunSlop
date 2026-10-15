#!/bin/sh
# Splice the desktop guest kernel into an nvkvm-kata checkout.
# Idempotent.
#
#   deploy/kata/apply-desktop-kernel.sh /path/to/nvkvm-kata
#   deploy/kata/apply-desktop-kernel.sh --self-test
#
# Run this before nvkvm-kata-install.sh, and pass that installer --graphics 1.
# The guest kernel must be >= 6.14 or CONFIG_NTSYNC is dropped and the
# kata build fails the fragment check.
#
# build-kernel.sh -g nvkvm only reads nvkvm.${arch}.conf.in. This script
# splices the fragment into that file, leaves a copy at
# kata/fragments/gpu/desktop.x86_64.conf, and teaches build-guest-kernel.sh
# to default CONFIG_MEMFD_CREATE on. That symbol's prompt exists only with
# CONFIG_EXPERT, which would turn off the syscalls Kata leaves at their
# defaults. Steam's runtime calls memfd_create.
set -eu

begin="# >>> gs-desktop >>>"
end="# <<< gs-desktop <<<"
hook_begin="# >>> gs-desktop memfd >>>"
hook_end="# <<< gs-desktop memfd <<<"

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
frag="$here/desktop.x86_64.conf"

die() {
    echo "apply-desktop-kernel: $*" >&2
    exit 1
}

need_symbol() {
    sym=$1
    file=$2
    grep -q "^${sym}=y$" "$file" || die "$file missing $sym=y"
}

forbid() {
    pat=$1
    file=$2
    why=$3
    if grep -q "$pat" "$file"; then
        die "$why"
    fi
}

splice_fragment() {
    src=$1
    dest=$2
    [ -f "$src" ] || die "no fragment $src"
    [ -f "$dest" ] || die "no nvkvm fragment $dest"
    tmp=$(mktemp)
    awk -v b="$begin" -v e="$end" '
        $0 == b { skip = 1; next }
        $0 == e { skip = 0; next }
        !skip { print }
    ' "$dest" > "$tmp"
    printf '%s\n' "$begin" >> "$tmp"
    cat "$src" >> "$tmp"
    printf '%s\n' "$end" >> "$tmp"
    mv "$tmp" "$dest"
}

# Hidden unless EXPERT. A default y is honored when the prompt is hidden.
# olddefconfig, not setup -f: setup -f deletes the tree and loses the edit.
memfd_hook() {
    cat <<'EOF'
    # >>> gs-desktop memfd >>>
    # CONFIG_MEMFD_CREATE's prompt is "if EXPERT". Kata's allnoconfig leaves
    # it off. EXPERT would also un-default eventfd, io_uring, and the rest
    # of the syscalls Kata does not list. Steam Linux Runtime calls memfd_create.
    gs_kcfg="$KPATH/mm/Kconfig"
    if [ -f "$gs_kcfg" ] && ! grep -q 'gs-desktop memfd default' "$gs_kcfg"; then
        gs_tmp=$(mktemp)
        awk '
            $0 == "config MEMFD_CREATE" {
                print
                print "\tdefault y"
                print "\t# gs-desktop memfd default"
                next
            }
            { print }
        ' "$gs_kcfg" > "$gs_tmp"
        mv "$gs_tmp" "$gs_kcfg"
        make -C "$KPATH" ARCH=x86 olddefconfig >/dev/null
        grep -q '^CONFIG_MEMFD_CREATE=y' "$KPATH/.config" \
            || die "CONFIG_MEMFD_CREATE did not stick; Steam Linux Runtime will not start"
    fi
    # <<< gs-desktop memfd <<<
EOF
}

splice_hook() {
    script=$1
    [ -f "$script" ] || die "no build script $script"
    anchor='grep -q '\''^CONFIG_MODULES=y'\'' "$KPATH/.config" \
        || die "CONFIG_MODULES is not set in the generated config -- the fragment did not apply"'
    grep -q 'CONFIG_MODULES is not set in the generated config' "$script" \
        || die "build-guest-kernel.sh has no CONFIG_MODULES anchor; nvkvm-kata moved"
    tmp=$(mktemp)
    awk -v b="$hook_begin" -v e="$hook_end" '
        index($0, b) { skip = 1; next }
        index($0, e) { skip = 0; next }
        !skip { print }
    ' "$script" > "$tmp"
    hook=$(mktemp)
    memfd_hook > "$hook"
    # Insert the hook immediately after the MODULES assertion, before build.
    inserted=$(mktemp)
    awk -v hook="$hook" '
        { print }
        /CONFIG_MODULES is not set in the generated config/ && !done {
            while ((getline line < hook) > 0) print line
            close(hook)
            done = 1
        }
    ' "$tmp" > "$inserted"
    grep -q 'gs-desktop memfd default' "$inserted" || die "memfd hook was not inserted"
    mv "$inserted" "$script"
    rm -f "$tmp" "$hook"
    chmod 0755 "$script" 2>/dev/null || true
}

check_fragment() {
    file=$1
    need_symbol CONFIG_INPUT_MISC "$file"
    need_symbol CONFIG_INPUT_UINPUT "$file"
    need_symbol CONFIG_HID_SUPPORT "$file"
    need_symbol CONFIG_HID "$file"
    need_symbol CONFIG_UHID "$file"
    need_symbol CONFIG_NTSYNC "$file"
    need_symbol CONFIG_FUSE_FS "$file"
    need_symbol CONFIG_FUSE_PASSTHROUGH "$file"
    need_symbol CONFIG_OVERLAY_FS "$file"
    need_symbol CONFIG_SQUASHFS "$file"
    need_symbol CONFIG_SQUASHFS_COMPILE_DECOMP_MULTI "$file"
    need_symbol CONFIG_IA32_EMULATION "$file"
    need_symbol CONFIG_SND_DUMMY "$file"
    need_symbol CONFIG_SND_SEQUENCER "$file"
    need_symbol CONFIG_USERFAULTFD "$file"
    need_symbol CONFIG_BINFMT_MISC "$file"
    need_symbol CONFIG_EFI "$file"
    need_symbol CONFIG_UCLAMP_TASK "$file"
    need_symbol CONFIG_TRANSPARENT_HUGEPAGE "$file"
    need_symbol CONFIG_IKCONFIG_PROC "$file"
    forbid '^CONFIG_LOCALVERSION=' "$file" "desktop fragment must not set LOCALVERSION"
    forbid 'CONFIG_MODULE_SIG_FORCE' "$file" "desktop fragment must not force module signatures"
    forbid '^CONFIG_.*=m$' "$file" "desktop fragment must be built-in (=y); the seat image has no modules tree"
    forbid '^CONFIG_HID_PID=' "$file" "HID_PID is not a 6.18 symbol and needs USB_HID"
    forbid '^CONFIG_SQUASHFS_DECOMP_MULTI=' "$file" "SQUASHFS_DECOMP_MULTI is hidden; set SQUASHFS_COMPILE_DECOMP_MULTI"
    forbid '^CONFIG_UDMABUF=' "$file" "UDMABUF depends on MEMFD_CREATE, which is not on during the fragment merge"
    forbid '^CONFIG_DRM' "$file" "DRM stays in the graphics fragment"
}

self_test() {
    check_fragment "$frag"
    tmp=$(mktemp -d)
    dest="$tmp/kata/fragments/gpu/nvkvm.x86_64.conf.in"
    script="$tmp/scripts/build-guest-kernel.sh"
    mkdir -p "$(dirname "$dest")" "$(dirname "$script")"
    printf '%s\n' "CONFIG_MODULES=y" "CONFIG_FUSE_FS=y" > "$dest"
    cat > "$script" <<'EOF'
#!/bin/sh
    grep -q '^CONFIG_MODULES=y' "$KPATH/.config" \
        || die "CONFIG_MODULES is not set in the generated config -- the fragment did not apply"
    ( cd "$OUT" && bash "$BK" -g nvkvm "${VARGS[@]}" build )
EOF
    splice_fragment "$frag" "$dest"
    splice_fragment "$frag" "$dest"
    count=$(grep -c -F "$begin" "$dest")
    [ "$count" = 1 ] || die "marker present $count times"
    need_symbol CONFIG_NTSYNC "$dest"
    need_symbol CONFIG_INPUT_UINPUT "$dest"
    need_symbol CONFIG_INPUT_MISC "$dest"
    head -n 1 "$dest" | grep -q '^CONFIG_MODULES=y$' || die "nvkvm prefix was eaten"
    mods=$(grep -c '^CONFIG_MODULES=y$' "$dest")
    [ "$mods" = 1 ] || die "CONFIG_MODULES duplicated"
    splice_hook "$script"
    splice_hook "$script"
    hooks=$(grep -c -F "$hook_begin" "$script")
    [ "$hooks" = 1 ] || die "memfd hook present $hooks times"
    grep -q 'olddefconfig' "$script" || die "memfd hook missing olddefconfig"
    # The MODULES line is still ahead of the hook, and build is still behind it.
    mods_line=$(grep -n 'CONFIG_MODULES is not set' "$script" | head -n 1 | cut -d: -f1)
    hook_line=$(grep -n -F "$hook_begin" "$script" | head -n 1 | cut -d: -f1)
    build_line=$(grep -n 'nvkvm "${VARGS\[@\]}" build' "$script" | head -n 1 | cut -d: -f1)
    [ "$mods_line" -lt "$hook_line" ] || die "hook landed above the MODULES anchor"
    [ "$hook_line" -lt "$build_line" ] || die "hook landed below the build"
    kcfg="$tmp/mm/Kconfig"
    mkdir -p "$tmp/mm"
    printf '%s\n' 'config MEMFD_CREATE' '	bool "Enable memfd_create() system call" if EXPERT' > "$kcfg"
    awk '
        $0 == "config MEMFD_CREATE" {
            print
            print "\tdefault y"
            print "\t# gs-desktop memfd default"
            next
        }
        { print }
    ' "$kcfg" > "$kcfg.tmp"
    mv "$kcfg.tmp" "$kcfg"
    grep -q '	default y' "$kcfg" || die "memfd default was not inserted"
    # A second pass must not stack another default. The build hook skips
    # when the marker is already present; mirror that here.
    if ! grep -q 'gs-desktop memfd default' "$kcfg"; then
        die "marker missing after one insertion"
    fi
    rm -rf "$tmp"
    echo "self-test ok"
}

if [ "${1:-}" = "--self-test" ]; then
    self_test
    exit 0
fi

[ $# = 1 ] || die "usage: apply-desktop-kernel.sh <nvkvm-kata-checkout>|--self-test"
root=$1
dest="$root/kata/fragments/gpu/nvkvm.x86_64.conf.in"
copy="$root/kata/fragments/gpu/desktop.x86_64.conf"
script="$root/scripts/build-guest-kernel.sh"
check_fragment "$frag"
splice_fragment "$frag" "$dest"
mkdir -p "$(dirname "$copy")"
cp "$frag" "$copy"
splice_hook "$script"
echo "apply-desktop-kernel: spliced into $dest"
echo "apply-desktop-kernel: copied to $copy (the build does not read this copy)"
echo "apply-desktop-kernel: memfd_create default hooked in $script"
echo "apply-desktop-kernel: rebuild with --graphics 1 so CONFIG_DRM is on. Kernel >= 6.14."
