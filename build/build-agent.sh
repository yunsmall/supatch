#!/bin/bash
# build-agent.sh - 用目标内核树构建 kpm_host.ko
#
# 用法：
#   KDIR=/path/to/kernel make -C 该目录的做法见下
#   KDIR=/path/to/kernel bash build/build-agent.sh
#
# 可选环境变量：
#   KDIR            必填，目标内核源码树（.config 需含 CONFIG_CFI_CLANG=y 等）
#   OUT             内核 build 目录（已单独 O= 配置过时使用）
#   CROSS_COMPILE   交叉工具链前缀，默认 aarch64-linux-gnu-
#   CC/LD/AR/NM/OBJCOPY  默认使用 PATH 里的 clang/ld.lld/llvm-*
#
# 产物：src/kpm_host.ko（vermagic 与目标内核一致）
#
# 注意：换内核必须重新构建，LKM 的 vermagic / MODVERSIONS / 结构体布局
# 都与目标内核绑定，不能一个 ko 跨版本。

set -e

if [ -z "$KDIR" ]; then
    echo "usage: KDIR=/path/to/kernel bash $0" >&2
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../src"

CC="${CC:-clang}"
LD="${LD:-ld.lld}"
AR="${AR:-llvm-ar}"
NM="${NM:-llvm-nm}"
OBJCOPY="${OBJCOPY:-llvm-objcopy}"
CROSS_COMPILE="${CROSS_COMPILE:-aarch64-linux-gnu-}"

MAKE_ARGS=(
    ARCH=arm64 LLVM=1 LLVM_IAS=1
    CC="$CC" LD="$LD" AR="$AR" NM="$NM" OBJCOPY="$OBJCOPY"
    CROSS_COMPILE="$CROSS_COMPILE"
    M="$SRC"
)

if [ -n "$OUT" ]; then
    MAKE_ARGS+=("O=$OUT")
fi

echo "[*] kernel: $KDIR"
echo "[*] toolchain: $CC / $LD"
make -C "$KDIR" "${MAKE_ARGS[@]}" modules

echo "[*] built: $SRC/kpm_host.ko"
modinfo -F vermagic "$SRC/kpm_host.ko" 2>/dev/null || true
