// SPDX-License-Identifier: GPL-2.0
/*
 * suzhi_loader.c - userspace driver for the resident /dev/suzhi_loader agent.
 *
 * Usage (run on the device as root):
 *   suzhi_loader load <kpm_host.ko> <suzhi_NQ.kpm> [kpm_args...]
 *       -- pushes kpm_host.ko with kpm_syms="kallsyms_lookup_name:0x<addr>",
 *          then hands the .kpm to the agent as ONE memory buffer via
 *          ioctl(LOAD). kpm_args (space separated) are forwarded verbatim
 *          as the .kpm init args.
 *   suzhi_loader unload      -- ioctl(UNLOAD)
 *   suzhi_loader status      -- ioctl(STATUS)
 *
 * The ioctl layout below MUST stay byte-identical to src/kpm_ctl.c.
 * This tool runs on the target ("adb shell su", arm64), so _IOW/_IOR size
 * encoding matches the kernel side there by construction.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#ifndef __NR_finit_module
#define __NR_finit_module 280 /* arm64 */
#endif
#ifndef __NR_delete_module
#define __NR_delete_module 106 /* arm64 */
#endif

#define DEV_NODE "/dev/suzhi_loader"

#define KPM_CTL_ARGS_MAX 256

struct kpm_ctl_load {
	const char *data;
	unsigned long len;
	char args[KPM_CTL_ARGS_MAX];
};

struct kpm_ctl_status {
	unsigned long base;
	unsigned long size;
	unsigned long text_size;
	char name[64];
	int loaded;
	int version;
};

#define KPM_CTL_IOCTL_BASE 'S'
#define SUZHI_LOADER_LOAD   _IOW(KPM_CTL_IOCTL_BASE, 1, struct kpm_ctl_load)
#define SUZHI_LOADER_UNLOAD _IO(KPM_CTL_IOCTL_BASE, 2)
#define SUZHI_LOADER_STATUS _IOR(KPM_CTL_IOCTL_BASE, 3, struct kpm_ctl_status)

static void dmesg_tail(void)
{
	FILE *f = popen("dmesg 2>/dev/null | tail -40", "r");
	char buf[256];

	if (!f)
		return;
	while (fgets(buf, sizeof(buf), f))
		fputs(buf, stderr);
	pclose(f);
}

/* find first type-T/t address for `want` in /proc/kallsyms */
static unsigned long ksym_lookup(const char *want)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char line[512];
	unsigned long addr = 0;

	if (!f) {
		perror("fopen /proc/kallsyms");
		return 0;
	}
	while (fgets(line, sizeof(line), f)) {
		char name[256];
		char type;
		unsigned long a;

		if (sscanf(line, "%lx %c %255s", &a, &type, name) != 3)
			continue;
		if (strcmp(name, want) == 0) {
			addr = a;
			break;
		}
	}
	fclose(f);
	return addr;
}

static int dev_open(void)
{
	int fd, tries;

	for (tries = 0; tries < 25; tries++) {
		fd = open(DEV_NODE, O_RDWR);
		if (fd >= 0)
			return fd;
		if (errno != ENOENT)
			break;
		usleep(100 * 1000);
	}
	fprintf(stderr, "open %s: %s (is the agent loaded?)\n",
		DEV_NODE, strerror(errno));
	return -1;
}

static int dev_exists(void)
{
	return access(DEV_NODE, F_OK) == 0;
}

static int do_load(const char *ko_path, const char *kpm_path, char **kpm_args,
		   int n_args, const char *anchor)
{
	unsigned long anchor_addr;
	char syms[2048];
	char *payload;
	struct stat st;
	struct kpm_ctl_load cl;
	int ko, fd, rc;

	if (!anchor)
		anchor = "kallsyms_lookup_name";
	anchor_addr = ksym_lookup(anchor);
	if (!anchor_addr) {
		fprintf(stderr, "anchor symbol %s not found in /proc/kallsyms\n",
			anchor);
		return 1;
	}
	printf("[*] anchor %s = 0x%lx\n", anchor, anchor_addr);

	snprintf(syms, sizeof(syms), "kpm_syms=%s:0x%lx", anchor, anchor_addr);
	printf("[*] agent params: %s\n", syms);

	/* if the agent node already exists, skip re-insmod (and avoid EEXIST) */
	if (dev_exists()) {
		printf("[*] agent already loaded, skipping insmod\n");
	} else {
		ko = open(ko_path, O_RDONLY);
		if (ko < 0) {
			perror("open agent ko");
			return 1;
		}
		rc = syscall(__NR_finit_module, ko, syms, 0);
		if (rc) {
			fprintf(stderr, "finit_module: %s (rc=%d)\n", strerror(errno), rc);
			close(ko);
			dmesg_tail();
			return 1;
		}
		close(ko);
		printf("[*] agent up\n");
		usleep(200 * 1000); /* let the node settle/finish coming up */
	}

	fd = dev_open();
	if (fd < 0)
		return 1;

	if (stat(kpm_path, &st) || st.st_size <= 0 || st.st_size > 16 * 1024 * 1024) {
		fprintf(stderr, "bad .kpm file %s\n", kpm_path);
		close(fd);
		return 1;
	}
	payload = malloc(st.st_size);
	if (!payload) {
		perror("malloc");
		close(fd);
		return 1;
	}
	{
		FILE *f = fopen(kpm_path, "rb");
		if (!f || fread(payload, 1, st.st_size, f) != (size_t)st.st_size) {
			fprintf(stderr, "read %s failed\n", kpm_path);
			if (f)
				fclose(f);
			free(payload);
			close(fd);
			return 1;
		}
		fclose(f);
	}

	memset(&cl, 0, sizeof(cl));
	cl.data = payload;
	cl.len = (unsigned long)st.st_size;

	/* forward the remaining CLI args verbatim as the .kpm init args */
	{
		size_t off = 0;
		int i;

		for (i = 0; i < n_args; i++) {
			int l = snprintf(cl.args + off, sizeof(cl.args) - off, "%s%s",
					 off ? " " : "", kpm_args[i]);
			if (l < 0 || (size_t)l >= sizeof(cl.args) - off)
				break;
			off += l;
		}
	}
	printf("[*] ioctl LOAD (%lu bytes, args: %s)\n", cl.len, cl.args);

	rc = ioctl(fd, SUZHI_LOADER_LOAD, &cl);
	if (rc) {
		fprintf(stderr, "ioctl LOAD: %s (rc=%d)\n", strerror(errno), rc);
		free(payload);
		close(fd);
		dmesg_tail();
		return 1;
	}
	free(payload);
	close(fd);
	printf("[*] .kpm loaded ok\n");
	return 0;
}

static int do_unload(void)
{
	int fd = dev_open();

	if (fd < 0)
		return 1;
	if (ioctl(fd, SUZHI_LOADER_UNLOAD)) {
		fprintf(stderr, "ioctl UNLOAD: %s\n", strerror(errno));
		close(fd);
		return 1;
	}
	close(fd);
	printf("[*] .kpm unloaded ok\n");
	return 0;
}

static int do_status(void)
{
	struct kpm_ctl_status st;
	int fd = dev_open();

	if (fd < 0)
		return 1;
	memset(&st, 0, sizeof(st));
	if (ioctl(fd, SUZHI_LOADER_STATUS, &st)) {
		fprintf(stderr, "ioctl STATUS: %s\n", strerror(errno));
		close(fd);
		return 1;
	}
	close(fd);
	printf("agent version = %d\n", st.version);
	printf("loaded        = %d\n", st.loaded);
	printf("iface name    = %s\n", st.name[0] ? st.name : "-");
	if (st.loaded) {
		printf("base          = 0x%lx\n", st.base);
		printf("size          = %lu\n", st.size);
		printf("text          = %lu\n", st.text_size);
	}
	return 0;
}

static void usage(void)
{
	fprintf(stderr,
		"usage:\n"
		"  %s load <kpm_host.ko> <suzhi_NQ.kpm> [kpm_args...]\n"
		"  %s unload\n"
		"  %s status\n"
		"  option: --anchor <kallsyms name>  (default: kallsyms_lookup_name)\n",
		"", "", "");
}

int main(int argc, char **argv)
{
	const char *anchor = NULL;
	int i = 1;

	if (argc < 2) {
		usage();
		return 1;
	}
	while (i < argc && strcmp(argv[i], "--anchor") == 0 && i + 1 < argc)
		anchor = argv[i += 2];

	if (strcmp(argv[i], "load") == 0) {
		if (argc - (i + 1) < 2) {
			usage();
			return 1;
		}
		return do_load(argv[i + 1], argv[i + 2],
			      argv + i + 3, argc - (i + 3), anchor);
	}
	if (strcmp(argv[i], "unload") == 0)
		return do_unload();
	if (strcmp(argv[i], "status") == 0)
		return do_status();
	usage();
	return 1;
}