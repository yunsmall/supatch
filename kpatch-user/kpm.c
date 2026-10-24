/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Copyright (C) 2026 yunsmall. All Rights Reserved.
 */

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <error.h>

#include "kpm.h"
#include "supercall.h"
#include "supatch.h"

/* KPatch 的 supercall 由内核态运行时 hook；没有它时退回 supatch 的
 * generic netlink 后端（配合常驻 kpm_host.ko 使用）。 */
static int supatch_mode(void)
{
    return !sc_ready() && supatch_available();
}

/* webui 按行解析 key=value；值里的换行会把一行拆成两行，输出前压成空格 */
static void print_field(const char *key, const char *val)
{
    const char *p;

    fprintf(stdout, "%s=", key);
    if (val) {
        for (p = val; *p; p++)
            fputc((*p == '\n' || *p == '\r') ? ' ' : *p, stdout);
    }
    fputc('\n', stdout);
}

int kpm_load(const char *path, const char *args)
{
    if (supatch_mode())
        return supatch_load(path, args);
    return sc_kpm_load(path, args, 0);
}

int kpm_control(const char *name, const char *ctl_args)
{
    char buf[4096] = { '\0' };
    int rc;

    if (supatch_mode()) {
        rc = supatch_ctl0(name, ctl_args, buf, sizeof(buf));
        fprintf(stdout, "%s", buf);
        return rc;
    }

    rc = sc_kpm_control(name, ctl_args, buf, sizeof(buf));
    /* 内核侧写满缓冲时也不保证 NUL，打印前强制截断 */
    buf[sizeof(buf) - 1] = '\0';
    fprintf(stdout, "%s", buf);
    return rc;
}

int kpm_unload(const char *name)
{
    if (supatch_mode())
        return supatch_unload(name);
    return sc_kpm_unload(name, 0);
}

int kpm_nums()
{
    if (supatch_mode()) {
        int nums = supatch_num();

        if (nums < 0)
            return nums;
        fprintf(stdout, "%d\n", nums);
        return 0;
    }

    int nums = sc_kpm_nums();
    fprintf(stdout, "%d\n", nums);
    return 0;
}

int kpm_list()
{
    if (supatch_mode()) {
        unsigned int i, count = 0;
        char mod_name[KPM_CTL_NAME_MAX];
        int rc = supatch_list(0, &count, NULL, 0);

        /* index 0 越界只说明当前没有模块，不是错误 */
        if (rc && rc != -ENOENT)
            return rc;
        for (i = 0; i < count; i++) {
            rc = supatch_list(i, NULL, mod_name, sizeof(mod_name));
            /* 两次 ioctl 之间可能有并发卸载，-ENOENT 视为列表结束 */
            if (rc == -ENOENT)
                break;
            if (rc)
                return rc;
            fprintf(stdout, "%s\n", mod_name);
        }
        return 0;
    }

    char buf[4096] = {0};
    int rc = sc_kpm_list(buf, sizeof(buf));
    if (rc > 0) {
        buf[sizeof(buf) - 1] = '\0';
        fprintf(stdout, "%s", buf);
        return 0;
    }
    return rc;
}

int kpm_info(const char *name)
{
    if (supatch_mode()) {
        struct kpm_ctl_status2 st;
        int rc = supatch_status(name, &st);

        if (rc)
            return rc;

        /* 字段名必须和 KPatch 的 modinfo 一致 */
        print_field("name", st.name);
        print_field("version", st.version);
        print_field("license", st.license);
        print_field("author", st.author);
        print_field("description", st.description);
        print_field("args", st.args);
        return 0;
    }

    char buf[4096] = {0};
    int rc = sc_kpm_info(name, buf, sizeof(buf));
    if (rc > 0) {
        buf[sizeof(buf) - 1] = '\0';
        fprintf(stdout, "%s", buf);
        return 0;
    }
    return rc;
}

extern const char program_name[];

static void usage(int status)
{
    if (status != EXIT_SUCCESS)
        fprintf(stderr, "Try `%s help' for more information.\n", program_name);
    else {
        printf("Usage: %s <COMMAND> [ARG]...\n\n", program_name);
        fprintf(stdout, ""
                        "KPatch-Next Module command set.\n"
                        "\n"
                        "help                           Print this help message. \n"
                        "load <KPM_PATH> [KPM_ARGS]     Load KPatch-Next Module with KPM_PATH and KPM_ARGS.\n"
                        "ctl0 <KPM_NAME> <CTL_ARGS>     Control KPatch-Next Module named KPM_PATH with CTL_ARGS.\n"
                        "unload <KPM_NAME>              Unload KPatch-Next Module named KPM_NAME.\n"
                        "num                            Get the number of modules that have been loaded.\n"
                        "list                           List names of all loaded modules.\n"
                        "info <KPM_NAME>                Get detailed information about module named KPM_NAME.\n"
                        "");
    }
    exit(status);
}

int kpm_main(int argc, char **argv)
{
    if (argc < 2) usage(EXIT_FAILURE);

    const char *scmd = argv[1];
    int cmd = -1;

    struct
    {
        const char *scmd;
        int cmd;
    } cmd_arr[] = {
        { "load", SUPERCALL_KPM_LOAD },
        { "ctl0", SUPERCALL_KPM_CONTROL },
        { "unload", SUPERCALL_KPM_UNLOAD },
        { "num", SUPERCALL_KPM_NUMS },
        { "list", SUPERCALL_KPM_LIST },
        { "info", SUPERCALL_KPM_INFO },
        { "help", 0 },
    };

    for (size_t i = 0; i < sizeof(cmd_arr) / sizeof(cmd_arr[0]); i++) {
        if (strcmp(scmd, cmd_arr[i].scmd)) continue;
        cmd = cmd_arr[i].cmd;
        break;
    }

    if (cmd < 0) usage(EXIT_FAILURE);

    const char *path = NULL;
    const char *mod_args = NULL;
    const char *ctl_args = NULL;
    const char *name = NULL;

    switch (cmd) {
    case SUPERCALL_KPM_LOAD:
        if (argc < 3) error(-EINVAL, 0, "module path does not exist");
        path = argv[2];
        mod_args = argc < 4 ? NULL : argv[3];
        return kpm_load(path, mod_args);
    case SUPERCALL_KPM_CONTROL:
        if (argc < 3) error(-EINVAL, 0, "module name does not exist");
        if (argc < 4) error(-EINVAL, 0, "control argument does not exist");
        name = argv[2];
        ctl_args = argv[3];
        return kpm_control(name, ctl_args);
    case SUPERCALL_KPM_UNLOAD:
        if (argc < 3) error(-EINVAL, 0, "module name does not exist");
        name = argv[2];
        return kpm_unload(name);
    case SUPERCALL_KPM_NUMS:
        return kpm_nums();
    case SUPERCALL_KPM_LIST:
        return kpm_list();
    case SUPERCALL_KPM_INFO:
        if (argc < 3) error(-EINVAL, 0, "module name does not exist");
        name = argv[2];
        return kpm_info(name);
    case 0:
        usage(EXIT_SUCCESS);
        break;
    default:
        usage(EXIT_FAILURE);
    }

    return 0;
}