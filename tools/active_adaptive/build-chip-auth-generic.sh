#!/bin/sh
# Build a card-agnostic CA-v1 npa-tool from pinned OpenSC + the generic include.
# Usage: build-chip-auth-generic.sh <source-checkout-dir>
# The source dir is cloned/reset to the pinned commit; treat it as untrusted.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOCAL="$ROOT/tools/pace-root/usr"
PATCH="$ROOT/tools/session/patches/npa-chip-auth-v1-exact.patch"
INC="$ROOT/active_adaptive/npa-ca-v1-generic.inc"
PINNED=c7b3d41676e0ba8104775a785bc6eba366002877
SRC=${1:?pass a source checkout directory}
OUT="$ROOT/active_adaptive/build/npa-tool-chip-auth-generic"

mkdir -p "$ROOT/active_adaptive/build"
if [ ! -d "$SRC/.git" ]; then
    git clone https://github.com/OpenSC/OpenSC "$SRC"
fi
git -C "$SRC" fetch --depth 1 origin "$PINNED" 2>/dev/null || true
git -C "$SRC" reset --hard "$PINNED"
git -C "$SRC" clean -fdq

cp "$INC" "$SRC/src/tools/npa-ca-v1-exact.inc"
git -C "$SRC" apply "$PATCH"

if [ ! -x "$SRC/configure" ]; then
    ( cd "$SRC" && ./bootstrap )
fi

BUILD="$SRC/build-ca"
mkdir -p "$BUILD"
( cd "$BUILD" && \
    PKG_CONFIG_PATH="$LOCAL/lib/x86_64-linux-gnu/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}" \
    CPPFLAGS="-I$LOCAL/include" \
    LDFLAGS="-L$LOCAL/lib/x86_64-linux-gnu -Wl,-rpath,$LOCAL/lib/x86_64-linux-gnu" \
    "$SRC/configure" --enable-openpace --disable-doc --disable-strict )
make -C "$BUILD/src" -j2
cp "$BUILD/src/tools/.libs/npa-tool" "$OUT"
chmod 0755 "$OUT"
echo "BUILT: $OUT"
sha256sum "$OUT"
