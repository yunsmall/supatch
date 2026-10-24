/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 yunsmall */
/*
 * supatch.h - supatch 后端：KPatch 内核运行时不存在时，通过 generic
 * netlink 和常驻 kpm_host.ko 通信（不创建 /dev 节点）。
 *
 * 结构体来自和 agent 共用的 include/kpm_ctl_uapi.h，避免两边各抄一份
 * 布局；共享头里的 _Static_assert 会盯住 ABI。
 */

#ifndef _KPU_SUPATCH_H_
#define _KPU_SUPATCH_H_

#include <stdbool.h>
#include <stddef.h>

#include "../include/kpm_ctl_uapi.h"

bool supatch_available(void);

/* name 为 NULL/空串时取第一个已加载模块 */
int supatch_status(const char *name, struct kpm_ctl_status2 *st);

/* index 从 0 开始；count 返回总数；index >= count 时返回 -ENOENT */
int supatch_list(unsigned int index, unsigned int *count, char *name,
                 size_t name_len);

int supatch_num(void);
int supatch_load(const char *path, const char *args);
int supatch_unload(const char *name);
int supatch_ctl0(const char *name, const char *ctl_args, char *out, int outlen);

#endif
