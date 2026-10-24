/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Copyright (C) 2026 yunsmall. All Rights Reserved.
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <error.h>

#include "../banner"
#include "../include/scdefs.h"
#include "kpatch.h"
#include "kpm.h"
#include "kpextension.h"
#include "rehook.h"
#include "supercall.h"
#include "supatch.h"

char program_name[128] = { '\0' };

/* argv[0] 由调用方控制，可能任意长；追加子命令前也要按剩余空间截断 */
static void append_program_name(const char *suffix)
{
    size_t used = strlen(program_name);

    if (used < sizeof(program_name))
        snprintf(program_name + used, sizeof(program_name) - used, "%s", suffix);
}

static void usage(int status)
{
    if (status != EXIT_SUCCESS) {
        fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
    } else {
        fprintf(stdout, "\nKPatch-Next userspace cli.\n");
        fprintf(stdout, KERNEL_PATCH_BANNER);
        fprintf(stdout,
                " \n"
                "Options: \n"
                "%s -h, --help       Print this help message. \n"
                "%s -v, --version    Print version. \n"
                "\n",
                program_name, program_name);
        fprintf(stdout, "Usage: %s <COMMAND> [-h, --help] [COMMAND_ARGS]...\n", program_name);
        fprintf(stdout,
                "\n"
                "Commands:\n"
                "hello              If KPatch-Next installed, '%s' will be echoed.\n"
                "kpver              Print KPatch-Next version.\n"
                "kver               Print Kernel version.\n"
                "kpm                KPatch-Next Module manager.\n"
                "exclude_set        Manage the exclude list.\n"
                "exclude_get        Get exclude list status.\n"
                "rehook             Set rehook mode (0=off, 1=target, 2=minimal).\n"
                "rehook_status      Check current rehook mode.\n"
                "\n",
                SUPERCALL_HELLO_ECHO);
    }
    exit(status);
}

// todo: refactor
int main(int argc, char **argv)
{
    snprintf(program_name, sizeof(program_name), "%s",
             argv[0] ? argv[0] : "kpatch");

    if (argc == 1) usage(EXIT_FAILURE);

    const char *scmd = argv[1];
    int cmd = -1;

    struct
    {
        const char *scmd;
        int cmd;
    } cmd_arr[] = {
        { "hello", SUPERCALL_HELLO },
        { "kpver", SUPERCALL_KERNELPATCH_VER },
        { "kver", SUPERCALL_KERNEL_VER },
        { "", 'K' },
        { "kpm", 'k' },
        { "exclude_set", 'e' },
        { "exclude_get", 'g' },
        { "rehook", 'r' },
        { "rehook_status", 'q' },

        { "bootlog", 'l' },
        { "panic", '.' },

        { "--help", 'h' },
        { "-h", 'h' },
        { "--version", 'v' },
        { "-v", 'v' },
    };

    for (size_t i = 0; i < sizeof(cmd_arr) / sizeof(cmd_arr[0]); i++) {
        if (strcmp(scmd, cmd_arr[i].scmd)) continue;
        cmd = cmd_arr[i].cmd;
        break;
    }

    if (cmd < 0) error(-EINVAL, 0, "Invalid command: %s!\n", scmd);

    switch (cmd) {
    case SUPERCALL_HELLO:
        hello();
        return 0;
    case SUPERCALL_KERNELPATCH_VER:
        kpv();
        return 0;
    case SUPERCALL_KERNEL_VER:
        kv();
        return 0;
    case 'k':
        append_program_name(" kpm");
        return kpm_main(argc - 1, argv + 1);
    case 'e':
        append_program_name(" exclude_set");
        return kpexclude_set_main(argc - 2, argv + 2);
    case 'g':
        append_program_name(" exclude_get");
        return kpexclude_get_main(argc - 2, argv + 2);
    case 'r':
        append_program_name(" rehook");
        if (!sc_ready() && supatch_available()) {
            fprintf(stderr, "%s: rehook is not supported by the supatch backend\n",
                    program_name);
            return -ENOTSUP;
        }
        return kprehook_main(argc - 2, argv + 2);
    case 'q':
        append_program_name(" rehook_status");
        if (!sc_ready() && supatch_available()) {
            /* status.sh 和 webui 都按 ":" 后半段判断状态；supatch 没有
             * rehook 机制，固定报告 disabled。 */
            fprintf(stdout, "rehook: disabled\n");
            return 0;
        }
        return kprehook_status_main(argc - 2, argv + 2);
    case 'l':
        bootlog();
        break;
    case '.':
        panic();
        break;

    case 'h':
        usage(EXIT_SUCCESS);
        break;
    case 'v':
        fprintf(stdout, "%x\n", version());
        break;

    default:
        fprintf(stderr, "Invalid command: %s!\n", scmd);
        return -EINVAL;
    }

    return 0;
}
