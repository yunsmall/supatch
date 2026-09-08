#!/bin/bash
# build/build_510.sh - build the resident KPM loader agent for GKI 5.10.
# The kbuild Makefile lives in ../src (M="$SRC"); run inside WSL as root:
#   bash build/build_510.sh
# KDIR must point at a 5.10 kernel tree prepared with CONFIG_CFI_CLANG=y
# (same tree the classic 工程\kpm_host\5.10 stack used).
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SRC="$ROOT/src"
TARGET="$HERE/kpm_host-gki-5.10.ko"
KDIR="${KDIR:-/root/kernel_common}"

echo "[*] ensure config has CFI"
grep -qx 'CONFIG_CFI_CLANG=y' "$KDIR/.config" \
  || { echo "FATAL: CONFIG_CFI_CLANG missing in $KDIR/.config"; exit 1; }

B=/root/prebuilt_clang/clang-r416183/bin
export PATH="$B:$PATH"
TVARS=(ARCH=arm64 LLVM=1 LLVM_IAS=1 CC="$B/clang" HOSTCC=gcc \
       NM="$B/llvm-nm" AR="$B/llvm-ar" LD="$B/ld.lld" \
       OBJCOPY="$B/llvm-objcopy" CROSS_COMPILE=aarch64-linux-gnu-)

echo "[*] syncconfig"
make -C "$KDIR" "${TVARS[@]}" syncconfig >/tmp/sync510.log 2>&1 \
  || { echo "FATAL syncconfig:"; tail -5 /tmp/sync510.log; exit 1; }

echo "[*] build"
make -C "$KDIR" "${TVARS[@]}" \
  KCFLAGS="-fsanitize-cfi-canonical-jump-tables -ffixed-x18" \
  M="$SRC" modules

echo "[*] verify cfi/slowpath symbols in the module"
readelf -Ws "$SRC/kpm_host.ko" | grep -iE 'cfi|slowpath' | head

cp -f "$SRC/kpm_host.ko" "$TARGET"
echo "=== done: $TARGET ==="
modinfo -F vermagic "$TARGET"
ls -l "$TARGET"