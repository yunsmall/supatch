# supatch

基于临时 root 的 LKM KPM 补丁加载方案（GKI 5.10 / 5.15 / 6.1 通用）。

在**临时 root**（`su`）环境下，通过 LKM 动态解析 `/proc/kallsyms` 的内核符号，
借由 `finit_module` 装入一个常驻加载器 agent，再由 agent 通过 ioctl 将 KPM
（Kernel Patch Module）整包作为内存缓冲直交装载进内核空间，注册 CFI shadow 并
执行，全程不依赖任何 KernelSU/APatch API。

## 特性

- **kprobe-free**：不注册任何 kprobe，通过用户态传入的「活表」锚点
  （`kallsyms_lookup_name` 地址）解析全部内核符号。
- **内存直交装载**：`.kpm` 不落盘，`copy_from_user → vmalloc → kpm_load_module`。
- **任意 KPM 兼容**：`.kpm` 为通用 ELF 格式，别人闭源的 KPM 同样适用。
- **跨内核版本**：所有符号运行时解析，一份 `.kpm` 可跨 GKI 5.10 / 5.15 / 6.1。
- **CFI shadow 注册**：aarch64 CFI 环境兼容。

## 目录结构

```
.
├── src/                内核侧源码（加载器 agent 本体）
│   ├── kpm_host_core.c 常驻 agent：活表解析 + 内存装载 + kpm_load_module
│   ├── kpm_host_re.c   aarch64 RELA 重定位
│   ├── kpm_ctl.c       /dev/suzhi_loader 控制节点 + ioctl(LOAD/UNLOAD/STATUS)
│   ├── kpm_insn.h      arm64 指令反汇编
│   ├── kpm_host.h      统一声明
│   └── Makefile        kbuild 构建
├── helper/
│   ├── suzhi_loader.c      用户态驱动：kallsyms 锚 → finit_module agent → ioctl
│   └── suzhi_loader_arm64  预编译 arm64 产物
├── build/
│   ├── build.sh / build_510.sh  构建脚本
│   ├── kpm_host-gki-5.10.ko     预编译 5.10 GKI agent
│   └── Makefile
└── test/
    └── smoke_510.sh    设备端冒烟测试
```

## 构建 agent

需要：WSL / Linux + 对应内核版本的树（`.config` 含 `CONFIG_CFI_CLANG=y`）+ Clang 工具链。

```bash
# 5.10 GKI
KDIR=<5.10 kernel tree> bash build/build_510.sh
# 产物: build/kpm_host-gki-5.10.ko
```

KPM（.kpm）本身由项目内其它工具链单独编译，不在本仓库内。

## 部署与使用

设备需满足硬性要求（工具启动时会自动自检）：

1. **root + CAP_SYS_MODULE**（`su` 运行）
2. **kernel.kptr_restrict=0**（工具自动置 0，等价于 `sysctl -w kernel.kptr_restrict=0`）
3. **/proc/kallsyms 可读且含 `kallsyms_lookup_name`**
4. **aarch64**，agent `.ko` 与内核 vermagic 匹配

命令行方式（`helper/suzhi_loader`）：

```bash
adb push helper/suzhi_loader                 /data/local/tmp/
adb push build/kpm_host-gki-5.10.ko          /data/local/tmp/
adb push <your.kpm>                          /data/local/tmp/

adb shell
su
cd /data/local/tmp
./suzhi_loader load kpm_host-gki-5.10.ko your.kpm   # 装载
./suzhi_loader status                              # 查看已装 KPM
./suzhi_loader unload                              # 卸载 KPM
rmmod kpm_host                                      # 卸载 agent
```

装载成功后可通过 `/dev/suzhi_loader` ioctl，以及 KPM 注册的 `/dev/<name>` 设备
与内核态功能交互（如硬件断点、内存读写等）。

## 硬性要求（自检清单）

| 项 | 要求 |
|---|---|
| 权限 | root + CAP_SYS_MODULE |
| 内核参数 | `kernel.kptr_restrict=0`（工具自动处理） |
| 符号表 | `/proc/kallsyms` 可读，锚 `kallsyms_lookup_name` 可见 |
| 架构 | aarch64 |
| 内核版本 | GKI 5.10 / 5.15 / 6.1（agent 需对应版本编译） |

## 说明

本方案基于 GKI 5.10 设计，思路文档见 `suzhi.md`。仅供研究参考。