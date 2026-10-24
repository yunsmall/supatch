/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2026 yunsmall */
/*
 * kpm_ctl_uapi.h - 内核/用户态共享的控制通道 ABI。
 *
 * 内核 agent 和用户态 kpatch 共用这一份定义，避免两边各抄一份结构体后
 * 悄悄漂移（ioctl 号里编码了 sizeof，一旦不一致内核会直接返回 EINVAL）。
 * 字段一律用固定宽度类型，指针也只以 u64 地址形式传递。
 */

#ifndef _KPM_CTL_UAPI_H_
#define _KPM_CTL_UAPI_H_

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/stddef.h>
typedef __u64 kpm_u64;
typedef __u32 kpm_u32;
#define KPM_UAPI_USER __user
#else
#include <stdint.h>
#include <stddef.h>
#include <sys/ioctl.h>
typedef uint64_t kpm_u64;
typedef uint32_t kpm_u32;
#define KPM_UAPI_USER
#endif

#define KPM_CTL_ARGS_MAX 256
#define KPM_CTL_NAME_MAX 64
#define KPM_CTL_VER_MAX 32
#define KPM_CTL_DESC_MAX 512
#define KPM_CTL_IMAGE_MAX (16ULL * 1024 * 1024)
#define KPM_CTL_MAX_MODULES 16

/* KPM 控制协议版本，kpatch kpver 会把它显示成 major.minor.patch */
#define KPM_CTL_VERSION_CODE 0x000101

struct kpm_ctl_load {
	kpm_u64 data; /* 用户态 KPM 镜像地址 */
	kpm_u64 len;
	char args[KPM_CTL_ARGS_MAX];
};

struct kpm_ctl_unload {
	char name[KPM_CTL_NAME_MAX];
};

struct kpm_ctl_status2 {
	kpm_u64 base;
	kpm_u64 size;
	kpm_u64 text_size;
	char name[KPM_CTL_NAME_MAX];
	char version[KPM_CTL_VER_MAX];
	char license[32];
	char author[32];
	char description[KPM_CTL_DESC_MAX];
	char args[KPM_CTL_ARGS_MAX];
	kpm_u32 loaded;
	kpm_u32 version_code;
};

/* name 为空时取第一个已加载模块，仅为兼容不支持按名字查询的旧调用方 */
struct kpm_ctl_status_req {
	char name[KPM_CTL_NAME_MAX];
	struct kpm_ctl_status2 st;
};

/* index 是输入序号；count 是输出总数；index >= count 时返回 -ENOENT */
struct kpm_ctl_list_req {
	kpm_u32 index;
	kpm_u32 count;
	char name[KPM_CTL_NAME_MAX];
};

struct kpm_ctl_ctl0 {
	char name[KPM_CTL_NAME_MAX];
	char args[KPM_CTL_ARGS_MAX];
	kpm_u64 out; /* 用户态输出缓冲区地址 */
	kpm_u32 outlen;
};

/*
 * 布局钉死：两边编译同一份头，任何字段顺序/类型变化都会在这里失败，
 * 而不是等到设备上 ioctl 返回 EINVAL 才发现。数值是当前 ABI 的快照。
 */
_Static_assert(sizeof(struct kpm_ctl_load) == 272, "kpm_ctl_load ABI");
_Static_assert(offsetof(struct kpm_ctl_load, len) == 8, "kpm_ctl_load ABI");
_Static_assert(offsetof(struct kpm_ctl_load, args) == 16, "kpm_ctl_load ABI");

_Static_assert(sizeof(struct kpm_ctl_unload) == 64, "kpm_ctl_unload ABI");

_Static_assert(sizeof(struct kpm_ctl_status2) == 960, "kpm_ctl_status2 ABI");
_Static_assert(offsetof(struct kpm_ctl_status2, name) == 24, "kpm_ctl_status2 ABI");
_Static_assert(offsetof(struct kpm_ctl_status2, version) == 88, "kpm_ctl_status2 ABI");
_Static_assert(offsetof(struct kpm_ctl_status2, license) == 120, "kpm_ctl_status2 ABI");
_Static_assert(offsetof(struct kpm_ctl_status2, author) == 152, "kpm_ctl_status2 ABI");
_Static_assert(offsetof(struct kpm_ctl_status2, description) == 184, "kpm_ctl_status2 ABI");
_Static_assert(offsetof(struct kpm_ctl_status2, args) == 696, "kpm_ctl_status2 ABI");
_Static_assert(offsetof(struct kpm_ctl_status2, loaded) == 952, "kpm_ctl_status2 ABI");
_Static_assert(offsetof(struct kpm_ctl_status2, version_code) == 956, "kpm_ctl_status2 ABI");

_Static_assert(sizeof(struct kpm_ctl_status_req) == 1024, "kpm_ctl_status_req ABI");
_Static_assert(offsetof(struct kpm_ctl_status_req, st) == 64, "kpm_ctl_status_req ABI");

_Static_assert(sizeof(struct kpm_ctl_list_req) == 72, "kpm_ctl_list_req ABI");
_Static_assert(offsetof(struct kpm_ctl_list_req, count) == 4, "kpm_ctl_list_req ABI");
_Static_assert(offsetof(struct kpm_ctl_list_req, name) == 8, "kpm_ctl_list_req ABI");

_Static_assert(sizeof(struct kpm_ctl_ctl0) == 336, "kpm_ctl_ctl0 ABI");
_Static_assert(offsetof(struct kpm_ctl_ctl0, args) == 64, "kpm_ctl_ctl0 ABI");
_Static_assert(offsetof(struct kpm_ctl_ctl0, out) == 320, "kpm_ctl_ctl0 ABI");
_Static_assert(offsetof(struct kpm_ctl_ctl0, outlen) == 328, "kpm_ctl_ctl0 ABI");

#define KPM_CTL_IOC_LOAD _IOW('S', 1, struct kpm_ctl_load)
#define KPM_CTL_IOC_UNLOAD _IOW('S', 2, struct kpm_ctl_unload)
#define KPM_CTL_IOC_CTL0 _IOW('S', 4, struct kpm_ctl_ctl0)
#define KPM_CTL_IOC_STATUS _IOWR('S', 5, struct kpm_ctl_status_req)
#define KPM_CTL_IOC_LIST _IOWR('S', 6, struct kpm_ctl_list_req)

/*
 * generic netlink 控制通道：不创建 /dev 节点，也不新增 /proc 条目。
 * 名字故意伪装成厂商风格；消息载荷是 kpm_genl_hdr + 对应结构体。
 */
#define KPM_GENL_FAMILY_NAME "oplus_dfr"
/* CTRL family 的 version 固定为 1；用户态对所有请求（包括 GETFAMILY）
 * 统一填这个值，改成别的数字会让 family 解析先失败。 */
#define KPM_GENL_VERSION 1
#define KPM_GENL_MAGIC 0x4b504d4e /* "KPMN" */

enum kpm_genl_cmd {
	KPM_GENL_CMD_LOAD = 1,
	KPM_GENL_CMD_UNLOAD = 2,
	KPM_GENL_CMD_STATUS = 3,
	KPM_GENL_CMD_CTL0 = 4,
	KPM_GENL_CMD_STATUS2 = 5,
	KPM_GENL_CMD_LIST = 6,
	KPM_GENL_CMD_REPLY = 7,
};

enum kpm_genl_attr {
	KPM_GENL_ATTR_UNSPEC,
	KPM_GENL_ATTR_PAYLOAD,
	__KPM_GENL_ATTR_MAX,
};
#define KPM_GENL_ATTR_MAX (__KPM_GENL_ATTR_MAX - 1)

struct kpm_genl_hdr {
	kpm_u32 magic;
	kpm_u32 cmd;
	kpm_u32 payload_len; /* hdr 之后的载荷长度 */
	kpm_u32 ret;         /* 响应时内核填返回值，请求时置 0 */
};

#endif /* _KPM_CTL_UAPI_H_ */
