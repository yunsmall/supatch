# kpatch-user（supatch 后端改造）

## 来源

- 上游：<https://github.com/KernelSU-Next/KPatch-Next> 的 `user/` 目录
  （GPL-2.0-or-later，Copyright (C) 2023 bmax121）。
- 本目录保留上游的文件结构与版权头，只做了下面列出的增量改动。

## 本 fork 的改动

1. **新增 `supatch.c` / `supatch.h`**：当 KPatch 内核运行时不存在
   （`sc_ready()` 失败）且 genl family `oplus_dfr` 可解析时，KPM 的
   load/unload/status/list/ctl0 全部改走 supatch agent 的 ioctl。
2. **`kpm.c`**：
   - `supatch_mode()` 后端判定；
   - `kpm list/info/unload/num/ctl0` 的 supatch 分派，输出格式对齐 KPatch-Next
     WebUI 的解析约定（list 每行一个名字；info 每行 `key=value`）；
   - 打印前强制 NUL（supercall 与 supatch 两个分支都做）。
3. **`kpatch.c`**：`hello()` / `kpv()` / `kv()` 增加 supatch 回退。
4. **`main.c`**：`rehook` / `rehook_status` 在 supatch 模式下返回
   `-ENOTSUP` / `rehook: disabled`；`program_name` 改用有界 `snprintf`。
5. **`supercall.h`**：补 `<stdint.h>`；`scdefs.h` 路径改为 `../include/scdefs.h`。
6. **构建**：
   - `Makefile`：加入 `supatch.c`、`-D_GNU_SOURCE`、`-I../include`、`LDFLAGS`；
   - `CMakeLists.txt`：加入 `supatch.c`、`../include`、`-D_GNU_SOURCE`、
     最低版本 3.13，并删除对 STATIC 库调用 `target_link_options`（CMake 会报错）。

## 构建

```bash
make CC=aarch64-linux-gnu-gcc LDFLAGS=-static
# 产物 kpatch：静态链接 aarch64，可直接替换 KPatch-Next 模块的 bin/kpatch
```

CMake 也可以（交叉编译时指定 `CMAKE_SYSTEM_NAME=Linux`、
`CMAKE_SYSTEM_PROCESSOR=aarch64`、`CMAKE_C_COMPILER=aarch64-linux-gnu-gcc`）。

## 与官方 kpatch 的兼容性

- 命令集、输出格式、退出码保持官方约定，WebUI 无需修改。
- `kpatch hello` 在 supatch 模式下输出 `hello2026`（与上游一致）。
- `kpatch kpver` 在 supatch 模式下输出 KPM 控制协议版本（`0x000101`）。
- 详见仓库根目录 `README.md` 的“用集成版 kpatch 替换官方可执行文件”。
