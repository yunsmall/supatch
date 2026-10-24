# supatch（fork）

基于临时 root 的 LKM KPM 加载方案。原版：<https://github.com/quanwei91/supatch>
（GKI 5.10 / 5.15 / 6.1）。本 fork 在保留原架构的前提下，增加了 6.12 GKI 适配、
多 KPM 支持，以及与官方 KPatch-Next WebUI 的无缝集成。

> 本仓库只包含加载器（agent + 用户态 CLI）源码。KPM 二进制、本地构建产物、
> 审查记录等均不随仓库发布（见 `.gitignore`）。

## 本 fork 相对原版的改动

- **6.12 GKI 适配**（android16-5，kCFI）：
  - `execmem_alloc` / `execmem_free`（6.10+）与 `module_alloc` / `module_memfree`
    （旧内核）运行时选择；
  - vmlinux text 用 `aarch64_insn_patch_text_nosync` 写入，8 字节补丁用
    `stop_machine` 包住；
  - CFI 失败路径补丁：6.12 的 `report_cfi_failure`，旧内核的
    `__cfi_slowpath_diag` / `__cfi_slowpath`；
  - 所有 CFI 类型 hash 离线核对，加载前无法关闭 CFI 失败路径时拒绝加载。
- **多 KPM**：最多同时驻留 `KPM_CTL_MAX_MODULES`（16）个镜像，UNLOAD / 查询 /
  ctl0 全部按 `.kpm.info` 里的 `name=` 寻址。
- **KPatch-Next WebUI 集成**：`kpatch-user/` 是官方 KPatch-Next CLI 的改造版，
  在 KPatch 内核运行时不存在时自动改走 `kpm_host` 的 generic netlink 通道
  （family `oplus_dfr`，不创建 `/dev` 节点），WebUI 的 KPM 列表 / 信息 /
  加载 / 卸载 / ctl0 / 数量全部可用。两种后端互不影响：`sc_ready()` 成功时
  仍优先走原 supercall。
- **健壮性修复**：ELF 段布局/重定位/modinfo 全边界检查、`sh_addralign` 与
  加法回绕防护、函数指针段最小长度、重复名字拒绝、`_Static_assert` 钉死
  ioctl ABI、ctl0 输出强制 NUL、错误路径回滚等。

## 目录结构

```
.
├── src/                        内核侧 agent
│   ├── kpm_host_core.c         活表解析、内存装载、ELF 布局/重定位、CFI 处理
│   ├── kpm_host_re.c           aarch64 RELA 重定位
│   ├── kpm_ctl.c               generic netlink 控制通道（LOAD/UNLOAD/STATUS/LIST/CTL0）
│   ├── kpm_insn.h              arm64 指令编码
│   ├── kpm_host.h              统一声明
│   └── Makefile                kbuild 构建
├── include/
│   ├── kpm_ctl_uapi.h          内核/用户态共享 ABI（结构体 + genl 消息，带布局断言）
│   ├── scdefs.h                KPatch supercall 常量（来自 KernelPatch，GPL-2.0-or-later）
│   ├── ktypes.h                用户态编译用的精简内核类型
│   └── compiler.h              用户态编译用的精简编译器宏
├── kpatch-user/                官方 KPatch-Next CLI 的 supatch 后端改造
│   ├── supatch.c / supatch.h   用户态 supatch 后端
│   ├── kpm.c / kpatch.c        KPM 命令与版本命令（新增 supatch 分派）
│   ├── main.c                  命令分发
│   ├── supercall.h             KPatch supercall 封装
│   ├── Makefile / CMakeLists.txt
│   └── README.md               来源与改动说明
├── helper/
│   ├── suzhi_loader.c          旧版 ioctl 驱动（仅适用于旧 ABI，genl 版不再使用）
│   └── suzhi_loader_arm64      预编译 arm64 产物
├── build/                      原版构建脚本与 5.10 预编译产物
└── test/                       设备端冒烟测试
```

## 构建

### agent（kpm_host.ko）

必须用**目标内核**的源码树构建（vermagic、MODVERSIONS、结构体布局都与内核绑定）。
以 Android GKI 为例：

```bash
# KDIR 指向已配置好的内核树（.config 含 CONFIG_CFI_CLANG=y），
# 工具链用与内核一致的 clang/LLVM。
make -C "$KDIR" ARCH=arm64 LLVM=1 LLVM_IAS=1 \
     CC=clang LD=ld.lld AR=llvm-ar NM=llvm-nm OBJCOPY=llvm-objcopy \
     M="$PWD/src" modules
# 产物：src/kpm_host.ko
```

> 不同内核版本需要分别构建。参考 `build/` 下的脚本（原版 5.10 路径）。

### kpatch（用户态 CLI）

```bash
cd kpatch-user
make CC=aarch64-linux-gnu-gcc LDFLAGS=-static
# 产物：kpatch（静态链接 aarch64，可直接放到 Android /data/adb 下运行）
```

Android NDK 构建也可以用 CMake（`cmake_minimum_required 3.13`）。静态链接是为了
不依赖 Android 上不存在的 glibc 动态加载器。

### KPM

KPM 是 KPatch 格式的 ELF（`ET_REL`, `EM_AARCH64`），需要单独编译：

```bash
clang --target=aarch64-none-elf -O2 -fno-builtin -nostdinc -ffreestanding \
      -fno-stack-protector -fno-pic -fno-pie -mno-outline-atomics \
      -fsanitize=kcfi \
      -I<KPatch-Next>/kernel -I<KPatch-Next>/kernel/include \
      -I<KPatch-Next>/kernel/patch/include \
      -I<KPatch-Next>/kernel/linux/include \
      -I<KPatch-Next>/kernel/linux/arch/arm64/include \
      -c -o my.kpm.o my.c
ld.lld -r -o my.kpm my.kpm.o
```

## 使用

### 前置条件

1. root + `CAP_SYS_MODULE`（ReSukiSU / KernelSU / Magisk 的 `su` 均可）；
2. `kernel.kptr_restrict=0`（否则 `/proc/kallsyms` 地址为 0）；
3. `/proc/kallsyms` 可读且包含 `kallsyms_lookup_name`；
4. aarch64，`kpm_host.ko` 与当前内核 vermagic / MODVERSIONS 匹配；
5. 内核未开启强制模块签名（`CONFIG_MODULE_SIG_FORCE`）。

### 加载 agent

```sh
su
echo 0 > /proc/sys/kernel/kptr_restrict
ADDR=$(grep ' kallsyms_lookup_name$' /proc/kallsyms | awk '{print $1}')
insmod /data/local/tmp/kpm_host.ko kpm_syms="kallsyms_lookup_name:0x$ADDR"
```

`helper/suzhi_loader` 是旧版 ioctl 驱动，只适用于旧 ABI；当前版本改用
generic netlink，请直接用 `kpatch kpm load`。

### 直接使用 generic netlink（不经 kpatch）

控制通道是 generic netlink family `oplus_dfr`，消息格式（`kpm_genl_hdr` +
业务结构体）和结构体定义在 `include/kpm_ctl_uapi.h`。常用命令：

| genl cmd | 作用 |
|---|---|
| `KPM_GENL_CMD_LOAD` | 传入 KPM 镜像（结构体里的用户态指针）+ args，创建一个新实例 |
| `KPM_GENL_CMD_UNLOAD` | 按名字卸载（空名卸载第一个） |
| `KPM_GENL_CMD_STATUS2` | 按名字查询 modinfo（空名取第一个） |
| `KPM_GENL_CMD_LIST` | 按 index 列举名字，返回总数 |
| `KPM_GENL_CMD_CTL0` | 按名字调用 KPM 的 ctl0 |
| `KPM_GENL_CMD_STATUS` | 旧版 STATUS，仅返回第一个（兼容旧脚本） |

不创建 `/dev` 节点，也不出现在 `/proc/devices`、`/proc/misc`、
`/proc/net/netlink` 里。

### 用集成版 kpatch 替换官方可执行文件

前提：已经安装 KPatch-Next-Module（Magisk/KernelSU 模块），模块目录下有官方的
`bin/kpatch`（通常几十 KB、动态链接 bionic）。本 fork 的 `kpatch` 是静态链接的
单文件，直接替换即可：

```sh
su
MOD=/data/adb/modules/KPatch-Next

# 1. 备份官方版本（只做一次）
cp -a "$MOD/bin/kpatch" "$MOD/bin/kpatch.orig"

# 2. 覆盖并恢复权限 / SELinux context
cp /data/local/tmp/kpatch "$MOD/bin/kpatch"
chown root:shell "$MOD/bin/kpatch"
chmod 755 "$MOD/bin/kpatch"
chcon u:object_r:system_file:s0 "$MOD/bin/kpatch"    # 或 restorecon

# 3. 验证
kpatch hello      # 输出 hello2026
kpatch kpver      # 输出 101（WebUI 显示 1.0.1）
kpatch kpm list   # 空或已加载模块列表
```

然后打开 KPatch-Next 的 WebUI：首页显示版本、KPM 页面可以加载/卸载/查看/ctl0。

### 不同发行版的替换方式

先确认设备上有没有独立的 `kpatch` 可执行文件：

```sh
su -c 'find /data/adb /system /vendor -name kpatch 2>/dev/null'
```

1. **ReSukiSU / KernelSU + KPatch-Next 模块**
   - 官方 CLI 在 `/data/adb/modules/KPatch-Next/bin/kpatch`，按上面的步骤替换。
   - 这是本 fork 的主要目标环境。
2. **APatch**
   - KernelPatch 内置在 boot 镜像里，用户态工具是 `apd`（APatch daemon），
     KPM 由 APatch Manager 管理；**没有独立的 `kpatch` CLI**，本 fork 的
     替换方式不适用。
   - 如果某个版本确实提供了 `kpatch` 二进制，可按 1 的方式替换（supercall
     后端与 KernelPatch 协议兼容）。
3. **SukiSU-Ultra**
   - KernelPatch 集成在 Manager / `ksud` 里，KPM 通常通过 Manager 的 KPM
     页面管理；是否提供独立 `kpatch` 取决于具体版本，用上面的 `find` 确认。
     有则按 1 替换，没有则无法用本 fork 的 CLI 替换。
4. **其他**
   - 只要设备上存在调用 KernelPatch supercall 的 `kpatch` CLI，就可以替换；
     完全没有 CLI（只有 Manager UI）的发行版无法接入。

**注意事项**

- **模块更新会覆盖**：KPatch-Next-Module 升级/重装后会写回官方 `bin/kpatch`，
  需要重新替换。
- **两种后端**：如果设备上同时存在 KPatch 内核运行时（supercall 生效），
  `kpatch` 会优先走原 supercall，supatch 后端不介入；只有在 `sc_ready()` 失败
  且 genl family `oplus_dfr` 可解析时才走 supatch。
- **agent 不会开机自启**：每次重启后需要重新 `insmod kpm_host.ko`（可以写进
  一个 KernelSU/Magisk 模块的 `service.sh`）。
- **不要直接 `rmmod kpm_host`**：每个已加载 KPM 都持有模块引用，先
  `kpatch kpm unload <name>` 卸掉所有 KPM，再 `rmmod`。直接 rmmod 会 `-EBUSY`。
- **KPM 文件位置**：WebUI 从 `/data/adb/kp-next/kpm/` 读取/删除 `.kpm`；也可以
  在 WebUI 里上传。命令行加载不受此目录限制。
- **单次加载多个**：最多 16 个，同名 KPM 会被拒绝（先卸载再加载）。
- **rehook**：supatch 没有 rehook 机制，`kpatch rehook_status` 固定输出
  `rehook: disabled`，`rehook enable/disable` 返回 `-ENOTSUP`。
- **版本号**：`kpver` 显示的是 KPM 控制协议版本（1.0.1），不是内核版本；
  内核版本用 `kpatch kver`（supatch 模式下来自 `uname()`）。
- **控制通道变更**：从 `/dev/suzhi_loader` ioctl 改为 generic netlink
  （family `oplus_dfr`），原来的 ioctl 号和 `helper/suzhi_loader.c` 都不再
  适用；请直接用 `kpatch`。
- **防检测**：genl 通道不创建 `/dev` 节点，`/proc/devices`、`/proc/misc`、
  `/proc/net/netlink` 都没有新增条目；但 `kpm_host` 这个 LKM 本身仍会在
  `/proc/modules`、`/sys/module/kpm_host` 可见，需要隐藏得另做 hook。
- **不要混用两个加载器**：KPatch 内核运行时加载的 KPM 与 supatch 加载的 KPM
  是两套独立实例，WebUI 在 supatch 模式下只看到后者。

## 多内核版本支持

supatch 是 LKM，vermagic / MODVERSIONS 无法绕过，因此多版本支持的做法是：

1. **每个目标内核构建一份 `kpm_host.ko`**（CI 矩阵），按 vermagic 命名分发；
2. **运行时符号探测**：`kallsyms_lookup_name` 锚点 + 符号存在性判断
   （`execmem_alloc` vs `module_alloc`、CFI 路径、`cfi_module_add` 等）；
3. **符号表外部注入**：`kpm_syms` 从 `/proc/kallsyms` 或 PC 端从 boot.img 的
   vmlinux 提取，换设备/换内核不用改代码；
4. **KPM 侧按目标内核 BTF 适配**：`struct kprobe` / `pt_regs` 等布局目前按设备
   BTF 手写，跨内核时需要重新核对（或从 BTF 自动生成）。

KernelPatch 之所以能“一份 kpimg 跨版本”，是因为它不是 LKM，而是直接把代码
patch 进内核镜像；supatch 没有这个前提，只能靠多份构建 + 运行时探测。

## 许可证与来源

- 本 fork 的修改与维护：yunsmall（2026）。各文件保留上游版权声明，新增修改的
  版权归 yunsmall 所有。
- 原版 supatch：<https://github.com/quanwei91/supatch>（原仓库未附 LICENSE；
  本 fork 按 GPL-2.0-or-later 发布，如原作者有不同意见请提出）。
- `kpatch-user/` 基于 KPatch-Next 的 user 源码（GPL-2.0-or-later，
  Copyright (C) 2023 bmax121），改动见 `kpatch-user/README.md`。
- `include/scdefs.h`、`include/ktypes.h`、`include/compiler.h` 来自
  KernelPatch / KPatch-Next（GPL-2.0-or-later）。
- 仅供研究与个人使用；加载内核模块有导致设备重启/数据丢失的风险，风险自负。
