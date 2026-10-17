#!/bin/bash
# Scan user homes and the common game libraries.
# A file whose size and mtime are unchanged is not scanned again.
# A hit is deleted and replaced by <name>.threat.txt.
# Infrastructure directories on the SSD root are skipped.
set -u

state="${CLAMAV_STATE:-/state/seen.tsv}"
scan_secs="${CLAMAV_SCAN_SECONDS:-300}"
update_secs="${CLAMAV_UPDATE_SECONDS:-7200}"
skip="${CLAMAV_SKIP:-gs-layer,proxy,clamav}"

declare -A seen

load_seen() {
  seen=()
  [[ -f "$state" ]] || return 0
  local mt sz path
  while IFS=$'\t' read -r mt sz path; do
    [[ -n "${path:-}" ]] || continue
    seen["$path"]="$mt $sz"
  done < "$state"
}

save_seen() {
  local tmp="$state.tmp" path
  mkdir -p "$(dirname "$state")"
  : > "$tmp"
  for path in "${!seen[@]}"; do
    printf '%s\t%s\n' "${seen[$path]// /$'\t'}" "$path" >> "$tmp"
  done
  mv -f "$tmp" "$state"
}

scan_file() {
  local f="$1" mt sz out code sig
  [[ -f "$f" ]] || return 0
  mt="$(stat -c %Y -- "$f")"
  sz="$(stat -c %s -- "$f")"
  if [[ "${seen[$f]:-}" == "$mt $sz" ]]; then
    return 0
  fi
  set +e
  out="$(clamscan --no-summary --stdout -- "$f" 2>/dev/null)"
  code=$?
  set -e
  if [[ "$code" -eq 1 ]]; then
    sig="${out##*: }"
    sig="${sig% FOUND}"
    rm -f -- "$f"
    unset 'seen[$f]'
    printf 'threat: %s\ndeleted: %s\n' "$sig" "$f" > "${f}.threat.txt"
    echo "clamav: deleted $f ($sig)"
    mt="$(stat -c %Y -- "${f}.threat.txt")"
    sz="$(stat -c %s -- "${f}.threat.txt")"
    seen["${f}.threat.txt"]="$mt $sz"
    return 0
  fi
  if [[ "$code" -ne 0 ]]; then
    echo "clamav: scan failed ($code) $f" >&2
    return 0
  fi
  seen["$f"]="$mt $sz"
}

scan_root() {
  local root="$1" f rel top expr
  [[ -d "$root" ]] || return 0
  expr=()
  local name first=1
  IFS=',' read -ra names <<< "$skip"
  for name in "${names[@]}"; do
    [[ -n "$name" ]] || continue
    if [[ "$first" -eq 1 ]]; then
      expr=( -path "$root/$name" )
      first=0
    else
      expr+=( -o -path "$root/$name" )
    fi
  done
  expr+=( -o -path "$root/lost+found" )
  local list
  list="$(mktemp)"
  find "$root" -xdev \( "${expr[@]}" \) -prune -o -type f -print0 > "$list"
  while IFS= read -r -d '' f; do
    rel="${f#"$root"/}"
    top="${rel%%/*}"
    case ",$skip," in
      *",$top,"*) continue ;;
    esac
    scan_file "$f"
  done < "$list"
  rm -f "$list"
}

scan_once() {
  local root
  load_seen
  for root in ${CLAMAV_ROOTS:-/scan/hdd /scan/ssd /scan/games /scan/gamessd}; do
    scan_root "$root"
  done
  # Drop cache rows whose file is gone.
  local path
  for path in "${!seen[@]}"; do
    [[ -f "$path" ]] || unset 'seen[$path]'
  done
  save_seen
}

update_db() {
  freshclam --quiet --datadir /var/lib/clamav || echo "clamav: freshclam failed" >&2
}

self_test() {
  local tmp bin calls
  tmp="$(mktemp -d)"
  bin="$tmp/bin"
  mkdir -p "$bin" "$tmp/ssd/alice" "$tmp/ssd/gs-layer" "$tmp/hdd/bob" "$tmp/state"
  echo clean > "$tmp/ssd/alice/ok.txt"
  echo bad > "$tmp/hdd/bob/bad.bin"
  echo secret > "$tmp/ssd/gs-layer/secret"
  printf '%s\n' '#!/bin/bash' 'echo freshclam' > "$bin/freshclam"
  cat > "$bin/clamscan" << 'EOF'
#!/bin/bash
f="${@: -1}"
echo "$f" >> "${CLAMAV_CALLS:?}"
if [[ "$f" == *bad.bin ]]; then
  echo "$f: Eicar-Test-Signature FOUND"
  exit 1
fi
echo "$f: OK"
exit 0
EOF
  chmod +x "$bin/freshclam" "$bin/clamscan"
  export PATH="$bin:$PATH"
  export CLAMAV_STATE="$tmp/state/seen.tsv"
  export CLAMAV_CALLS="$tmp/calls"
  export CLAMAV_ROOTS="$tmp/hdd $tmp/ssd"
  export CLAMAV_SKIP="gs-layer,proxy,clamav"
  : > "$CLAMAV_CALLS"
  set -e
  scan_once
  [[ ! -f "$tmp/hdd/bob/bad.bin" ]] || { echo "infected file was kept" >&2; exit 1; }
  grep -q "Eicar-Test-Signature" "$tmp/hdd/bob/bad.bin.threat.txt"
  [[ -f "$tmp/ssd/gs-layer/secret" ]] || { echo "layer was scanned" >&2; exit 1; }
  [[ -f "$tmp/ssd/alice/ok.txt" ]] || { echo "clean file was removed" >&2; exit 1; }
  calls="$(wc -l < "$CLAMAV_CALLS")"
  : > "$CLAMAV_CALLS"
  scan_once
  [[ ! -s "$CLAMAV_CALLS" ]] || { echo "unchanged files were scanned again" >&2; exit 1; }
  echo changed >> "$tmp/ssd/alice/ok.txt"
  scan_once
  grep -q "ok.txt" "$CLAMAV_CALLS" || { echo "changed file was not scanned" >&2; exit 1; }
  echo "clamav self-test ok"
}

if [[ "${1:-}" == "--self-test" ]]; then
  set -e
  self_test
  exit 0
fi

set -e
mkdir -p /var/lib/clamav "$(dirname "$state")"
update_db
next_update="$(date +%s)"
while true; do
  now="$(date +%s)"
  if [[ "$now" -ge "$next_update" ]]; then
    update_db
    next_update="$((now + update_secs))"
  fi
  scan_once
  sleep "$scan_secs"
done
