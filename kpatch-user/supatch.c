/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 yunsmall */
/*
 * supatch.c - supatch 后端实现。
 *
 * 走 generic netlink 和常驻 kpm_host.ko 通信，不再创建 /dev 节点。
 * 命令号和结构体来自共享的 include/kpm_ctl_uapi.h；family id 每次调用
 * 时向内核查询，模块重载后也不会拿到过期的 id。
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>

#include "supatch.h"

#define KPM_NL_RESP_MAX 4096

static uint32_t kpm_nl_seq;

/* 打开 NETLINK_GENERIC socket；portid 交给内核分配 */
static int nl_open(int timeout_sec)
{
	struct sockaddr_nl sa;
	struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
	if (fd < 0)
		return -errno;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		int rc = -errno;

		close(fd);
		return rc;
	}

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

/*
 * 发一条 genl 请求。data 放在 attr_type 属性里；返回 seq（>0）或负错误。
 * resolve 和业务请求的属性类型不同，所以属性类型由调用方指定。
 */
static int nl_send(int fd, uint16_t type, uint8_t cmd, uint16_t flags,
		   uint16_t attr_type, const void *data, size_t data_len)
{
	size_t nla_len = NLA_HDRLEN + data_len;
	size_t nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN + NLA_ALIGN(nla_len);
	struct sockaddr_nl dst;
	struct nlmsghdr *nlh;
	struct genlmsghdr *gh;
	struct nlattr *na;
	char *buf;
	uint32_t seq;
	ssize_t n;
	int rc = 0;

	buf = calloc(1, nlmsg_len);
	if (!buf)
		return -ENOMEM;

	seq = ++kpm_nl_seq;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = nlmsg_len;
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = flags;
	nlh->nlmsg_seq = seq;

	gh = (struct genlmsghdr *)(buf + NLMSG_HDRLEN);
	gh->cmd = cmd;
	gh->version = KPM_GENL_VERSION;

	na = (struct nlattr *)(buf + NLMSG_HDRLEN + GENL_HDRLEN);
	na->nla_type = attr_type;
	na->nla_len = nla_len;
	if (data_len)
		memcpy((char *)na + NLA_HDRLEN, data, data_len);

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;

	n = sendto(fd, buf, nlmsg_len, 0, (struct sockaddr *)&dst, sizeof(dst));
	if (n < 0)
		rc = -errno;
	else if ((size_t)n != nlmsg_len)
		rc = -EIO;

	free(buf);
	return rc < 0 ? rc : (int)seq;
}

/* 查询 genl family id；CTRL 响应的属性布局和业务消息不同，单独解析 */
static int nl_resolve_family(int fd, const char *name)
{
	char buf[512];
	int seq;
	ssize_t n;

	seq = nl_send(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, NLM_F_REQUEST,
		      CTRL_ATTR_FAMILY_NAME, name, strlen(name) + 1);
	if (seq < 0)
		return seq;

	for (;;) {
		int remain;
		struct nlmsghdr *nlh;

		n = recv(fd, buf, sizeof(buf), 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}

		remain = (int)n;
		for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, remain);
		     nlh = NLMSG_NEXT(nlh, remain)) {
			struct genlmsghdr *gh;
			struct nlattr *na;
			int alen;

			if (nlh->nlmsg_seq != (uint32_t)seq)
				continue;
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				int err;

				if (nlh->nlmsg_len <
				    NLMSG_HDRLEN + sizeof(struct nlmsgerr))
					continue;
				err = ((struct nlmsgerr *)NLMSG_DATA(nlh))->error;
				/* CTRL 找不到 family 时返回 -ENOENT，和
				 * LIST 的索引越界不是一回事。 */
				return err == -ENOENT ? -ENODEV : err;
			}

			gh = (struct genlmsghdr *)NLMSG_DATA(nlh);
			alen = nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
			na = (struct nlattr *)((char *)gh + GENL_HDRLEN);
			while (alen >= (int)NLA_HDRLEN &&
			       na->nla_len >= NLA_HDRLEN &&
			       NLA_ALIGN(na->nla_len) <= alen) {
				if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
					uint16_t id;

					/* 畸形/截断响应不能越界读 */
					if (na->nla_len <
					    NLA_HDRLEN + sizeof(id))
						return -EIO;
					memcpy(&id, (char *)na + NLA_HDRLEN,
					       sizeof(id));
					return id;
				}
				alen -= NLA_ALIGN(na->nla_len);
				na = (struct nlattr *)((char *)na +
						      NLA_ALIGN(na->nla_len));
			}
			return -ENODEV;
		}
	}
}

/* 接收业务响应：解析 kpm_genl_hdr，把载荷拷到 resp */
static int nl_recv(int fd, uint32_t seq, void *resp, size_t *resp_len)
{
	char buf[KPM_NL_RESP_MAX];
	size_t cap = resp_len ? *resp_len : 0;
	ssize_t n;

	for (;;) {
		int remain;
		struct nlmsghdr *nlh;

		n = recv(fd, buf, sizeof(buf), 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (resp_len)
				*resp_len = 0;
			return -errno;
		}

		remain = (int)n;
		for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, remain);
		     nlh = NLMSG_NEXT(nlh, remain)) {
			struct genlmsghdr *gh;
			struct nlattr *na;
			struct kpm_genl_hdr kh;
			int alen;

			if (nlh->nlmsg_seq != seq)
				continue;
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				int err;

				if (nlh->nlmsg_len <
				    NLMSG_HDRLEN + sizeof(struct nlmsgerr))
					continue;
				err = ((struct nlmsgerr *)NLMSG_DATA(nlh))->error;
				if (resp_len)
					*resp_len = 0;
				/* family 在 resolve 之后被注销时也是 -ENOENT，
				 * 不能和 LIST 的索引越界混为一谈。 */
				return err == -ENOENT ? -ENODEV : err;
			}

			gh = (struct genlmsghdr *)NLMSG_DATA(nlh);
			alen = nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
			if (alen < (int)NLA_HDRLEN)
				continue;

			na = (struct nlattr *)((char *)gh + GENL_HDRLEN);
			if (na->nla_type != KPM_GENL_ATTR_PAYLOAD ||
			    na->nla_len < NLA_HDRLEN ||
			    na->nla_len > alen ||
			    (size_t)(na->nla_len - NLA_HDRLEN) < sizeof(kh))
				continue;

			memcpy(&kh, (char *)na + NLA_HDRLEN, sizeof(kh));
			if (kh.magic != KPM_GENL_MAGIC ||
			    kh.payload_len > na->nla_len - NLA_HDRLEN -
						     sizeof(kh))
				continue;

			/* 业务返回值可能是 -ENOENT 但载荷仍有效（LIST 的
			 * count），所以是否拷贝只看有没有收到响应，不看 rc。 */
			if (resp && resp_len) {
				size_t copy = kh.payload_len;

				if (copy > cap)
					copy = cap;
				memcpy(resp, (char *)na + NLA_HDRLEN + sizeof(kh),
				       copy);
				*resp_len = copy;
			} else if (resp_len) {
				*resp_len = 0;
			}
			return (int32_t)kh.ret;
		}
	}
}

/* 一次完整调用：开 socket、查 family、发请求、等响应、关 socket */
static int nl_call(uint8_t cmd, const void *payload, size_t len,
		   void *resp, size_t *resp_len, int timeout_sec)
{
	struct kpm_genl_hdr hdr = {
		.magic = KPM_GENL_MAGIC,
		.cmd = cmd,
		.payload_len = (kpm_u32)len,
		.ret = 0,
	};
	size_t cap = resp_len ? *resp_len : 0;
	char *buf;
	int fd, family_id, seq, rc;

	/* 默认“没有收到响应”；所有 early return 都保持这个值 */
	if (resp_len)
		*resp_len = 0;

	buf = malloc(sizeof(hdr) + len);
	if (!buf)
		return -ENOMEM;
	memcpy(buf, &hdr, sizeof(hdr));
	if (len)
		memcpy(buf + sizeof(hdr), payload, len);

	fd = nl_open(timeout_sec);
	if (fd < 0) {
		free(buf);
		return fd;
	}

	family_id = nl_resolve_family(fd, KPM_GENL_FAMILY_NAME);
	if (family_id < 0) {
		close(fd);
		free(buf);
		return family_id;
	}

	seq = nl_send(fd, (uint16_t)family_id, cmd, NLM_F_REQUEST,
		      KPM_GENL_ATTR_PAYLOAD, buf, sizeof(hdr) + len);
	free(buf);
	if (seq < 0) {
		close(fd);
		return seq;
	}

	rc = nl_recv(fd, (uint32_t)seq, resp, resp_len ? &cap : NULL);
	close(fd);

	/* nl_recv 已按“是否收到响应”设置长度，这里不再按 rc 覆盖 */
	if (resp_len)
		*resp_len = cap;
	return rc;
}

bool supatch_available(void)
{
	int fd, id;

	fd = nl_open(5);
	if (fd < 0)
		return false;
	id = nl_resolve_family(fd, KPM_GENL_FAMILY_NAME);
	close(fd);
	return id > 0;
}

int supatch_status(const char *name, struct kpm_ctl_status2 *st)
{
	struct kpm_ctl_status_req req;
	size_t resp_len = sizeof(req);
	int rc;

	if (!st)
		return -EINVAL;
	if (name && strlen(name) >= KPM_CTL_NAME_MAX)
		return -ENAMETOOLONG;

	memset(&req, 0, sizeof(req));
	if (name)
		snprintf(req.name, sizeof(req.name), "%s", name);

	rc = nl_call(KPM_GENL_CMD_STATUS2, &req, sizeof(req), &req, &resp_len,
		     5);
	if (rc)
		return rc;
	if (resp_len < sizeof(req))
		return -EIO;
	*st = req.st;
	return 0;
}

int supatch_list(unsigned int index, unsigned int *count, char *name,
		 size_t name_len)
{
	struct kpm_ctl_list_req req;
	size_t resp_len = sizeof(req);
	int rc;

	memset(&req, 0, sizeof(req));
	req.index = (kpm_u32)index;

	rc = nl_call(KPM_GENL_CMD_LIST, &req, sizeof(req), &req, &resp_len, 5);

	/* 即使 -ENOENT，内核也会把 count 带回来 */
	if (resp_len >= sizeof(req)) {
		if (count)
			*count = req.count;
		if (name && name_len)
			snprintf(name, name_len, "%s", req.name);
	}
	return rc;
}

int supatch_num(void)
{
	unsigned int count = 0;
	int rc = supatch_list(0, &count, NULL, 0);

	/* -ENODEV 是 family 不存在（agent 没加载），不能当成 0 个模块 */
	if (rc == -ENODEV)
		return rc;
	/* index 0 越界只说明当前没有模块，不是错误 */
	if (rc && rc != -ENOENT)
		return rc;
	return (int)count;
}

int supatch_load(const char *path, const char *args)
{
	struct kpm_ctl_load arg;
	struct stat st;
	char *buf = NULL;
	size_t off = 0;
	ssize_t n;
	int fd, rc;
	size_t resp_len = 0;

	if (!path || !path[0])
		return -EINVAL;
	/* 静默截断会把半个 UTF-8 或半个过滤词交给 KPM，宁可明确报错 */
	if (args && strlen(args) >= KPM_CTL_ARGS_MAX)
		return -E2BIG;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	if (fstat(fd, &st)) {
		rc = -errno;
		goto out;
	}
	if (!S_ISREG(st.st_mode) || st.st_size <= 0 ||
	    (unsigned long long)st.st_size > KPM_CTL_IMAGE_MAX) {
		rc = -EINVAL;
		goto out;
	}

	/* 镜像太大，不能塞进单个 netlink attribute；内核会按这个
	 * 用户态地址 copy_from_user。 */
	buf = malloc((size_t)st.st_size);
	if (!buf) {
		rc = -ENOMEM;
		goto out;
	}

	memset(&arg, 0, sizeof(arg));
	arg.data = (kpm_u64)(uintptr_t)buf;
	arg.len = (kpm_u64)st.st_size;
	snprintf(arg.args, sizeof(arg.args), "%s", args ? args : "");

	while (off < (size_t)st.st_size) {
		n = read(fd, buf + off, (size_t)st.st_size - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			rc = -errno;
			goto out;
		}
		if (n == 0) {
			rc = -EIO;
			goto out;
		}
		off += (size_t)n;
	}

	/* 镜像拷贝/重定位可能超过查询类命令的 5 秒超时 */
	rc = nl_call(KPM_GENL_CMD_LOAD, &arg, sizeof(arg), NULL, &resp_len, 30);

out:
	free(buf);
	close(fd);
	return rc;
}

int supatch_unload(const char *name)
{
	struct kpm_ctl_unload arg;
	size_t resp_len = 0;

	if (name && strlen(name) >= KPM_CTL_NAME_MAX)
		return -ENAMETOOLONG;

	memset(&arg, 0, sizeof(arg));
	if (name)
		snprintf(arg.name, sizeof(arg.name), "%s", name);

	return nl_call(KPM_GENL_CMD_UNLOAD, &arg, sizeof(arg), NULL, &resp_len,
		       5);
}

int supatch_ctl0(const char *name, const char *ctl_args, char *out, int outlen)
{
	struct kpm_ctl_ctl0 arg;
	size_t resp_len = 0;
	int rc;

	if (!out || outlen <= 0)
		return -EINVAL;
	if (name && strlen(name) >= KPM_CTL_NAME_MAX)
		return -ENAMETOOLONG;
	if (ctl_args && strlen(ctl_args) >= KPM_CTL_ARGS_MAX)
		return -E2BIG;

	/* KPM 可能只写一部分且不写 NUL，调用方会按 %s 打印；
	 * 先清零，避免把未初始化内容当字符串输出。 */
	memset(out, 0, outlen);

	memset(&arg, 0, sizeof(arg));
	if (name)
		snprintf(arg.name, sizeof(arg.name), "%s", name);
	snprintf(arg.args, sizeof(arg.args), "%s", ctl_args ? ctl_args : "");
	arg.out = (kpm_u64)(uintptr_t)out;
	arg.outlen = (kpm_u32)outlen;

	rc = nl_call(KPM_GENL_CMD_CTL0, &arg, sizeof(arg), NULL, &resp_len, 5);

	/* KPM 的 ctl0 没有义务写 NUL 终止符；调用方随后会按字符串打印，
	 * 这里强制截断，避免读越界。 */
	out[outlen - 1] = '\0';
	return rc;
}
