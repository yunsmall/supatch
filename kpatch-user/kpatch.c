/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Copyright (C) 2026 yunsmall. All Rights Reserved.
 */

#include "kpatch.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <linux/capability.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <error.h>

#include "supercall.h"
#include "supatch.h"

uint32_t version()
{
    uint32_t version_code = (MAJOR << 16) + (MINOR << 8) + PATCH;
    return version_code;
}

void hello()
{
    long ret = sc_hello();

    if (ret == SUPERCALL_HELLO_MAGIC) {
        fprintf(stdout, "%s\n", SUPERCALL_HELLO_ECHO);
        return;
    }
    /* 没有 KPatch 运行时、但 supatch agent 已就绪时也输出同一魔术串：
     * webui 以 hello 输出非空作为“已安装”的判据。 */
    if (supatch_available())
        fprintf(stdout, "%s\n", SUPERCALL_HELLO_ECHO);
}

void kpv()
{
    if (!sc_ready() && supatch_available()) {
        struct kpm_ctl_status2 st;
        unsigned int ver = KPM_CTL_VERSION_CODE;

        /* 没有 KPM 时 STATUS 返回 -ENOENT，但协议版本本身仍可报告；
         * 不能落到 sc_kp_ver()，那里会输出 ffffffda 这种垃圾值。 */
        if (!supatch_status(NULL, &st))
            ver = (unsigned int)st.version_code;
        fprintf(stdout, "%x\n", ver);
        return;
    }

    uint32_t kpv = sc_kp_ver();
    fprintf(stdout, "%x\n", kpv);
}

void kv()
{
    if (!sc_ready() && supatch_available()) {
        struct utsname u;
        unsigned int major = 0, minor = 0, patch = 0;

        /* supatch 没有 KPatch 的 kver supercall；直接用 uname 的
         * release 字段，编码保持 major<<16 | minor<<8 | patch。 */
        if (uname(&u) == 0)
            sscanf(u.release, "%u.%u.%u", &major, &minor, &patch);
        fprintf(stdout, "%x\n", (major << 16) | (minor << 8) | patch);
        return;
    }

    uint32_t kv = sc_k_ver();
    fprintf(stdout, "%x\n", kv);
}

void bootlog()
{
    sc_bootlog();
}

void panic()
{
    sc_panic();
}
