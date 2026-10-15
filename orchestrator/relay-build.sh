#!/bin/sh
# Compile gs-relay in the proxy container. The image ships the compiler and
# the source, not a binary. A matching stamp skips the compile on a second
# start of the same container filesystem.
set -eu
src=/usr/local/src/gs-relay
dest=/usr/local/bin/gs-relay
stamp=/var/cache/gs-relay/source.stamp

if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
  echo "gs-relay: installing rustc and cargo" >&2
  dnf -y install rust cargo gcc
fi

cd "$src"
current="$(find Cargo.toml Cargo.lock src -type f ! -path '*/target/*' | sort | xargs sha256sum | sha256sum | awk '{print $1}')"
if [ -x "$dest" ] && [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$current" ]; then
  echo "gs-relay: source unchanged, using $dest"
  exit 0
fi

echo "gs-relay: compiling"
cargo build --release --offline --locked
install -m 0755 target/release/gs-relay "$dest"
mkdir -p "$(dirname "$stamp")"
printf '%s\n' "$current" > "$stamp"
echo "gs-relay: installed $dest"
