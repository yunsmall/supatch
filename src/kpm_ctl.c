// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2026 yunsmall */
/*
 * kpm_ctl.c - resident KPM loader agent 的控制通道。
 *
 * 用 generic netlink 而不是字符设备：不创建 /dev 节点，不产生
 * /proc/devices、/proc/misc 条目；genl 复用系统已有的 NETLINK_GENERIC
 * 内核 socket，/proc/net/netlink 也不会多出记录。
 *
 * 请求载荷是 kpm_genl_hdr + 对应结构体；LOAD 的镜像是 16MiB 级别，
 * 单条 netlink attribute 放不下，仍通过结构体里的用户态指针传递。
 * genl doit 在发送者进程上下文执行，所以 copy_from_user/copy_to_user
 * 的语义和原来的 ioctl 一致。
 *
 * 最多同时驻留 KPM_CTL_MAX_MODULES 个镜像；UNLOAD/STATUS2/LIST/CTL0 都按
 * 模块名（.kpm.info 里的 name=）寻址，和 KPatch-Next WebUI 的约定一致。
 *
 * 权限：netlink_capable(skb, CAP_SYS_MODULE)，和原 ioctl 的 open 检查一致。
 * 所有路径用 kpm_ctl_lock 串行化；每个驻留 KPM 持有本模块的一个引用，
 * 因此 rmmod 会返回 -EBUSY。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <linux/capability.h>
#include <net/genetlink.h>

#include "kpm_host.h"

/* 旧版 STATUS 只返回第一个已加载镜像，保留给还在用它的调试工具。 */
struct kpm_ctl_status {
	unsigned long base;
	unsigned long size;
	unsigned long text_size;
	char name[64];
	int loaded;
	int version;
};

static DEFINE_MUTEX(kpm_ctl_lock);

/* 调用者必须持有 kpm_ctl_lock */
static struct kpm_image *kpm_find_by_name(const char *name)
{
	int i;

	for (i = 0; i < KPM_CTL_MAX_MODULES; i++) {
		struct kpm_image *img = &kpm_images[i];

		if (!img->loaded || !img->info_name)
			continue;
		if (!strcmp(img->info_name, name))
			return img;
	}
	return NULL;
}

static struct kpm_image *kpm_first_loaded(void)
{
	int i;

	for (i = 0; i < KPM_CTL_MAX_MODULES; i++) {
		if (kpm_images[i].loaded)
			return &kpm_images[i];
	}
	return NULL;
}

/* 排除刚加载、还没计入 other 的那个槽位 */
static bool kpm_name_conflicts(const struct kpm_image *self)
{
	int i;

	/* 正常加载路径会拒绝没有 name 的 KPM；这里兜底，避免 strcmp
	 * 解引用 NULL */
	if (!self->info_name)
		return false;

	for (i = 0; i < KPM_CTL_MAX_MODULES; i++) {
		const struct kpm_image *img = &kpm_images[i];

		if (img == self || !img->loaded || !img->info_name)
			continue;
		if (!strcmp(img->info_name, self->info_name))
			return true;
	}
	return false;
}

static struct kpm_image *kpm_find_free_slot(void)
{
	int i;

	for (i = 0; i < KPM_CTL_MAX_MODULES; i++) {
		if (!kpm_images[i].base && !kpm_images[i].loaded)
			return &kpm_images[i];
	}
	return NULL;
}

/*
 * LOAD 载荷是 struct kpm_ctl_load；镜像太大，不放 skb，仍按 data
 * 用户态指针 copy_from_user 进来。
 */
static long kpm_do_load(const void *payload, unsigned int len)
{
	struct kpm_ctl_load arg;
	struct kpm_image *img;
	void *buf;
	long rc;

	if (len < sizeof(arg))
		return -EINVAL;
	memcpy(&arg, payload, sizeof(arg));
	arg.args[sizeof(arg.args) - 1] = '\0';

	/* 镜像最大 16MiB，单条 netlink attribute 的 u16 长度放不下，
	 * 所以仍按用户态指针拷贝，和旧 ioctl 路径一致。 */
	if (!arg.data || !arg.len || arg.len > KPM_CTL_IMAGE_MAX)
		return -EINVAL;

	mutex_lock(&kpm_ctl_lock);
	img = kpm_find_free_slot();
	if (!img) {
		mutex_unlock(&kpm_ctl_lock);
		return -ENOSPC;
	}

	buf = vmalloc(arg.len);
	if (!buf) {
		mutex_unlock(&kpm_ctl_lock);
		return -ENOMEM;
	}
	if (copy_from_user(buf, (void __user *)(unsigned long)arg.data,
			   arg.len)) {
		vfree(buf);
		mutex_unlock(&kpm_ctl_lock);
		return -EFAULT;
	}

	rc = kpm_load_module(img, buf, arg.len, arg.args, "load", NULL);
	vfree(buf);

	if (rc)
		goto out;

	/* 名字在 KPM 文件里，只有加载成功后才能查重。重名时把刚加载的
	 * 镜像完整卸载（init 已经跑过，exit 会清理），避免两个同名镜像
	 * 无法按名字寻址。 */
	if (kpm_name_conflicts(img)) {
		pr_err("kpm: duplicate module name: %s\n", img->info_name);
		kpm_unload_image(img);
		rc = -EEXIST;
		goto out;
	}

	if (!try_module_get(THIS_MODULE)) {
		/* 拿不到自引用说明模块正在被 rmmod，立即拆掉刚加载的 KPM */
		kpm_unload_image(img);
		rc = -EBUSY;
		goto out;
	}
	rc = 0;
out:
	mutex_unlock(&kpm_ctl_lock);
	return rc;
}

static long kpm_do_unload(const void *payload, unsigned int len)
{
	struct kpm_ctl_unload arg;
	struct kpm_image *img;

	if (len < sizeof(arg))
		return -EINVAL;
	memcpy(&arg, payload, sizeof(arg));
	arg.name[sizeof(arg.name) - 1] = '\0';

	mutex_lock(&kpm_ctl_lock);
	/* 空名字兼容旧调用方：卸载第一个 */
	img = arg.name[0] ? kpm_find_by_name(arg.name) : kpm_first_loaded();
	if (!img) {
		mutex_unlock(&kpm_ctl_lock);
		return -ENOENT;
	}
	kpm_unload_image(img);
	module_put(THIS_MODULE);
	mutex_unlock(&kpm_ctl_lock);
	return 0;
}

static long kpm_do_ctl0(const void *payload, unsigned int len)
{
	struct kpm_ctl_ctl0 arg;
	struct kpm_image *img;
	long rc;

	if (len < sizeof(arg))
		return -EINVAL;
	memcpy(&arg, payload, sizeof(arg));
	arg.name[sizeof(arg.name) - 1] = '\0';
	arg.args[sizeof(arg.args) - 1] = '\0';
	if (!arg.out || !arg.outlen || arg.outlen > (kpm_u32)INT_MAX)
		return -EINVAL;

	/* 与 load/unload 互斥：ctl0 执行期间镜像不能被释放 */
	mutex_lock(&kpm_ctl_lock);
	img = arg.name[0] ? kpm_find_by_name(arg.name) : kpm_first_loaded();
	if (!img) {
		mutex_unlock(&kpm_ctl_lock);
		return -ENOENT;
	}
	rc = kpm_call_ctl0(img, arg.args,
			   (char __user *)(unsigned long)arg.out,
			   (int)arg.outlen);
	mutex_unlock(&kpm_ctl_lock);
	return rc;
}

static long kpm_do_status(struct kpm_ctl_status *st)
{
	struct kpm_image *img;

	mutex_lock(&kpm_ctl_lock);
	memset(st, 0, sizeof(*st));
	st->version = 1;
	img = kpm_first_loaded();
	if (img) {
		st->loaded = 1;
		st->base = (unsigned long)img->base;
		st->size = img->size;
		st->text_size = img->text_size;
		if (img->info_name)
			strscpy(st->name, img->info_name, sizeof(st->name));
	}
	mutex_unlock(&kpm_ctl_lock);
	return 0;
}

static void kpm_fill_status(struct kpm_ctl_status2 *st,
			    const struct kpm_image *img)
{
	memset(st, 0, sizeof(*st));
	st->loaded = img->loaded ? 1 : 0;
	st->base = (kpm_u64)(unsigned long)img->base;
	st->size = img->size;
	st->text_size = img->text_size;
	st->version_code = KPM_CTL_VERSION_CODE;
	if (img->info_name)
		strscpy(st->name, img->info_name, sizeof(st->name));
	if (img->info_version)
		strscpy(st->version, img->info_version, sizeof(st->version));
	if (img->info_license)
		strscpy(st->license, img->info_license, sizeof(st->license));
	if (img->info_author)
		strscpy(st->author, img->info_author, sizeof(st->author));
	if (img->info_description)
		strscpy(st->description, img->info_description,
			sizeof(st->description));
	/* info_args 是内嵌数组而不是指针，strscpy 永远不会读到 NULL */
	strscpy(st->args, img->info_args, sizeof(st->args));
}

static long kpm_do_status2(const void *payload, unsigned int len,
			   struct kpm_ctl_status_req *out)
{
	struct kpm_ctl_status_req req;
	struct kpm_image *img;
	long rc = 0;

	if (len < sizeof(req))
		return -EINVAL;
	memcpy(&req, payload, sizeof(req));
	req.name[sizeof(req.name) - 1] = '\0';

	mutex_lock(&kpm_ctl_lock);
	img = req.name[0] ? kpm_find_by_name(req.name) : kpm_first_loaded();
	if (!img)
		rc = -ENOENT;
	else
		kpm_fill_status(&req.st, img);
	mutex_unlock(&kpm_ctl_lock);

	if (!rc)
		*out = req;
	return rc;
}

static long kpm_do_list(const void *payload, unsigned int len,
			struct kpm_ctl_list_req *out)
{
	struct kpm_ctl_list_req req;
	unsigned int seen = 0, count = 0;
	int i, rc = 0;

	if (len < sizeof(req))
		return -EINVAL;
	memcpy(&req, payload, sizeof(req));

	mutex_lock(&kpm_ctl_lock);
	for (i = 0; i < KPM_CTL_MAX_MODULES; i++) {
		if (kpm_images[i].loaded)
			count++;
	}
	req.count = count;
	memset(req.name, 0, sizeof(req.name));
	if (req.index >= count) {
		rc = -ENOENT;
		goto out;
	}
	for (i = 0; i < KPM_CTL_MAX_MODULES; i++) {
		struct kpm_image *img = &kpm_images[i];

		if (!img->loaded)
			continue;
		if (seen++ != req.index)
			continue;
		if (img->info_name)
			strscpy(req.name, img->info_name, sizeof(req.name));
		break;
	}
out:
	mutex_unlock(&kpm_ctl_lock);

	/* 即使 -ENOENT 也把 count 带回去，调用方据此结束循环 */
	*out = req;
	return rc;
}

/* ── generic netlink 层 ───────────────────────────────────────────── */

static int kpm_genl_doit(struct sk_buff *skb, struct genl_info *info);

/*
 * 6.12 的 genl 注册会把 cmd >= resv_start_op 且没有 policy 的 op 填成
 * NLA_REJECT，导致我们唯一的 PAYLOAD 属性被框架直接拒绝（-EINVAL）。
 * 把 resv_start_op 设到所有命令之后，并给每个 op 声明 maxattr，
 * 属性才能按默认策略解析。
 */
static const struct genl_ops kpm_genl_ops[] = {
	{ .cmd = KPM_GENL_CMD_LOAD, .doit = kpm_genl_doit,
	  .maxattr = KPM_GENL_ATTR_MAX },
	{ .cmd = KPM_GENL_CMD_UNLOAD, .doit = kpm_genl_doit,
	  .maxattr = KPM_GENL_ATTR_MAX },
	{ .cmd = KPM_GENL_CMD_STATUS, .doit = kpm_genl_doit,
	  .maxattr = KPM_GENL_ATTR_MAX },
	{ .cmd = KPM_GENL_CMD_CTL0, .doit = kpm_genl_doit,
	  .maxattr = KPM_GENL_ATTR_MAX },
	{ .cmd = KPM_GENL_CMD_STATUS2, .doit = kpm_genl_doit,
	  .maxattr = KPM_GENL_ATTR_MAX },
	{ .cmd = KPM_GENL_CMD_LIST, .doit = kpm_genl_doit,
	  .maxattr = KPM_GENL_ATTR_MAX },
};

static struct genl_family kpm_genl_family = {
	.name = KPM_GENL_FAMILY_NAME,
	.version = KPM_GENL_VERSION,
	.maxattr = KPM_GENL_ATTR_MAX,
	.resv_start_op = KPM_GENL_CMD_REPLY + 1,
	/* LOAD 会在 doit 里 copy_from_user，不能持 genl 全局锁睡眠 */
	.parallel_ops = 1,
	.module = THIS_MODULE,
	.ops = kpm_genl_ops,
	.n_ops = ARRAY_SIZE(kpm_genl_ops),
};

static int kpm_genl_reply(struct genl_info *info, long rc,
			  const void *data, unsigned int data_len)
{
	struct sk_buff *skb;
	struct kpm_genl_hdr hdr;
	void *msg;
	u8 *buf;
	int ret;

	skb = genlmsg_new(nla_total_size(sizeof(hdr) + data_len), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	msg = genlmsg_put(skb, info->snd_portid, info->snd_seq,
			  &kpm_genl_family, 0, KPM_GENL_CMD_REPLY);
	if (!msg) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	hdr.magic = KPM_GENL_MAGIC;
	hdr.cmd = KPM_GENL_CMD_REPLY;
	hdr.payload_len = data_len;
	hdr.ret = (kpm_u32)rc;

	buf = kmalloc(sizeof(hdr) + data_len, GFP_KERNEL);
	if (!buf) {
		nlmsg_free(skb);
		return -ENOMEM;
	}
	memcpy(buf, &hdr, sizeof(hdr));
	if (data_len)
		memcpy(buf + sizeof(hdr), data, data_len);

	ret = nla_put(skb, KPM_GENL_ATTR_PAYLOAD, sizeof(hdr) + data_len, buf);
	kfree(buf);
	if (ret) {
		nlmsg_free(skb);
		return ret;
	}

	genlmsg_end(skb, msg);
	return genlmsg_reply(skb, info);
}

static int kpm_genl_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *na;
	struct kpm_genl_hdr hdr;
	const u8 *p;
	unsigned int len;
	long rc;
	struct kpm_ctl_status st;
	struct kpm_ctl_status_req req;
	struct kpm_ctl_list_req list;
	const void *resp = NULL;
	unsigned int resp_len = 0;

	/* netlink_capable 检查的是发送方 netns 的 user_ns，非特权用户可以
	 * 创建 user+net namespace 拿到 CAP_SYS_MODULE；加载内核代码必须
	 * 检查 init_user_ns 的能力。 */
	if (!capable(CAP_SYS_MODULE))
		return kpm_genl_reply(info, -EPERM, NULL, 0);

	na = info->attrs[KPM_GENL_ATTR_PAYLOAD];
	if (!na)
		return kpm_genl_reply(info, -EINVAL, NULL, 0);

	p = nla_data(na);
	len = nla_len(na);
	if (len < sizeof(hdr))
		return kpm_genl_reply(info, -EINVAL, NULL, 0);

	memcpy(&hdr, p, sizeof(hdr));
	if (hdr.magic != KPM_GENL_MAGIC)
		return kpm_genl_reply(info, -EINVAL, NULL, 0);
	p += sizeof(hdr);
	len -= sizeof(hdr);
	if (hdr.payload_len != len)
		return kpm_genl_reply(info, -EINVAL, NULL, 0);

	switch (hdr.cmd) {
	case KPM_GENL_CMD_LOAD:
		rc = kpm_do_load(p, len);
		break;
	case KPM_GENL_CMD_UNLOAD:
		rc = kpm_do_unload(p, len);
		break;
	case KPM_GENL_CMD_STATUS:
		rc = kpm_do_status(&st);
		resp = &st;
		resp_len = sizeof(st);
		break;
	case KPM_GENL_CMD_CTL0:
		rc = kpm_do_ctl0(p, len);
		break;
	case KPM_GENL_CMD_STATUS2:
		rc = kpm_do_status2(p, len, &req);
		if (!rc) {
			resp = &req;
			resp_len = sizeof(req);
		}
		break;
	case KPM_GENL_CMD_LIST:
		rc = kpm_do_list(p, len, &list);
		if (!rc || rc == -ENOENT) {
			resp = &list;
			resp_len = sizeof(list);
		}
		break;
	default:
		rc = -EOPNOTSUPP;
		break;
	}

	return kpm_genl_reply(info, rc, resp, resp_len);
}

int kpm_ctl_init(void)
{
	int rc = genl_register_family(&kpm_genl_family);

	if (rc)
		pr_err("kpm: ctl: genl_register_family failed rc=%d\n", rc);
	else
		pr_alert("kpm: ctl: genl family %s ready\n",
			 KPM_GENL_FAMILY_NAME);
	return rc;
}

void kpm_ctl_exit(void)
{
	genl_unregister_family(&kpm_genl_family);
	pr_info("kpm: ctl: genl family removed\n");
}
