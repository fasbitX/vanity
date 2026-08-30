#!/usr/bin/env bash
#
# Fetch samr7/vanitygen at a pinned commit, apply the OpenSSL 3 / PCRE2 port,
# and build it.
#
# vanitygen is AGPL-3.0 and this project is MIT, so the source is never
# committed here: it is cloned into vendor/vanitygen (gitignored) and driven as
# a subprocess. Only the patch lives in the repo.
#
set -euo pipefail

REPO=https://github.com/samr7/vanitygen.git
# vanitygen 0.22, the last upstream commit (2013).
COMMIT=cd1a7282431dcf7e522777976aa18728ee5bb7be

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="$root/vendor/vanitygen"
patch="$root/vendor/patches/0001-openssl3-pcre2.patch"

need() {
    command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 1; }
}
need git; need make; need cc; need pkg-config

for lib in libcrypto libpcre2-8; do
    pkg-config --exists "$lib" || {
        echo "missing $lib development headers." >&2
        echo "  sudo apt install libssl-dev libpcre2-dev" >&2
        exit 1
    }
done

if [ ! -d "$src/.git" ]; then
    echo "==> cloning vanitygen"
    mkdir -p "$root/vendor"
    git clone "$REPO" "$src"
fi

echo "==> checking out $COMMIT"
git -C "$src" fetch --quiet origin || true
git -C "$src" checkout --quiet --force "$COMMIT"
git -C "$src" clean -qfd -e '*.o' -e vanitygen -e keyconv

echo "==> applying $(basename "$patch")"
git -C "$src" apply --whitespace=nowarn "$patch"

echo "==> building"
make -C "$src" clean >/dev/null 2>&1 || true
# `most` only: the OpenCL targets need OpenSSL internals that 3.x does not
# expose. See the patch header.
make -C "$src" most

echo
"$src/vanitygen" 2>&1 | head -1
echo "built: $src/vanitygen"
echo "       $src/keyconv"
