// SPDX-License-Identifier: GPL-2.0
/*
 * kpm_ctl.c - resident KPM loader agent control node.
 *
 * Provides /dev/suzhi_loader with ioctl(LOAD/UNLOAD/STATUS). The actual
 * KPM ELF image is handed to the kernel as a whole memory buffer
 * (copy_from_user -> vmalloc), so no firmware file nor filp_open/kernel_read
 * is required anywhere on the load path.
 *
 * Method: open() is gated on capable(CAP_SYS_MODULE). Serialization between
 * load/unload is done with a mutex. While a KPM image is resident the module
 * holds a reference on itself so rmmod fails with -EBUSY (and thus never
 * tears the loaded image down underneath the agent).
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/capability.h>
#include <linux/string.h>

#include "kpm_host.h"

#define KPM_CTL_VERSION 1

#define KPM_CTL_IOCTL_BASE 'S'
#define SUZHI_LOADER_LOAD   _IOW(KPM_CTL_IOCTL_BASE, 1, struct kpm_ctl_load)
#define SUZHI_LOADER_UNLOAD _IO(KPM_CTL_IOCTL_BASE, 2)
#define SUZHI_LOADER_STATUS _IOR(KPM_CTL_IOCTL_BASE, 3, struct kpm_ctl_status)

#define KPM_CTL_ARGS_MAX 256
#define KPM_CTL_IMAGE_MAX (16 * 1024 * 1024)

struct kpm_ctl_load {
	const char __user *data;
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

static DEFINE_MUTEX(kpm_ctl_lock);

static int kpm_ctl_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_MODULE))
		return -EPERM;
	return 0;
}

static int kpm_ctl_release(struct inode *inode, struct file *file)
{
	return 0;
}

static long kpm_ctl_load(struct kpm_ctl_load __user *uarg)
{
	struct kpm_ctl_load arg;
	void *buf;
	long rc;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	if (!arg.data || arg.len == 0 || arg.len > KPM_CTL_IMAGE_MAX)
		return -EINVAL;

	arg.args[sizeof(arg.args) - 1] = '\0';

	mutex_lock(&kpm_ctl_lock);
	if (kpm_is_loaded()) {
		mutex_unlock(&kpm_ctl_lock);
		return -EBUSY;
	}

	buf = vmalloc(arg.len);
	if (!buf) {
		mutex_unlock(&kpm_ctl_lock);
		return -ENOMEM;
	}

	if (copy_from_user(buf, arg.data, arg.len)) {
		vfree(buf);
		mutex_unlock(&kpm_ctl_lock);
		return -EFAULT;
	}

	rc = kpm_load_module(buf, arg.len, arg.args, "load", NULL);
	vfree(buf);

	if (rc)
		goto out;

	if (!try_module_get(THIS_MODULE))
		pr_err("kpm: ctl: failed to hold module ref, rmmod while loaded!\n");
	rc = 0;
out:
	mutex_unlock(&kpm_ctl_lock);
	return rc;
}

static long kpm_ctl_unload(void)
{
	long rc = 0;

	mutex_lock(&kpm_ctl_lock);
	if (!kpm_is_loaded()) {
		mutex_unlock(&kpm_ctl_lock);
		return -EINVAL;
	}
	kpm_unload_current();
	module_put(THIS_MODULE);
	mutex_unlock(&kpm_ctl_lock);
	return rc;
}

static long kpm_ctl_status(struct kpm_ctl_status __user *ust)
{
	struct kpm_ctl_status st;

	mutex_lock(&kpm_ctl_lock);
	memset(&st, 0, sizeof(st));
	st.version = KPM_CTL_VERSION;
	st.loaded = kpm_is_loaded();
	st.base = (unsigned long)kpm_image.base;
	st.size = kpm_image.size;
	st.text_size = kpm_image.text_size;
	if (kpm_image.info_name)
		strscpy(st.name, kpm_image.info_name, sizeof(st.name));
	mutex_unlock(&kpm_ctl_lock);

	if (copy_to_user(ust, &st, sizeof(st)))
		return -EFAULT;
	return 0;
}

static long kpm_ctl_ioctl(struct file *file, unsigned int cmd, unsigned long uarg)
{
	switch (cmd) {
	case SUZHI_LOADER_LOAD:
		return kpm_ctl_load((struct kpm_ctl_load __user *)uarg);
	case SUZHI_LOADER_UNLOAD:
		return kpm_ctl_unload();
	case SUZHI_LOADER_STATUS:
		return kpm_ctl_status((struct kpm_ctl_status __user *)uarg);
	default:
		return -ENOIOCTLCMD;
	}
}

static const struct file_operations kpm_ctl_fops = {
	.owner = THIS_MODULE,
	.open = kpm_ctl_open,
	.release = kpm_ctl_release,
	.unlocked_ioctl = kpm_ctl_ioctl,
	.compat_ioctl = kpm_ctl_ioctl,
};

static struct miscdevice kpm_ctl_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "suzhi_loader",
	.fops = &kpm_ctl_fops,
};

int kpm_ctl_init(void)
{
	int rc = misc_register(&kpm_ctl_dev);

	if (rc)
		pr_err("kpm: ctl: misc_register failed rc=%d\n", rc);
	else
		pr_alert("kpm: ctl: /dev/suzhi_loader ready (min %d)\n",
			 kpm_ctl_dev.minor);
	return rc;
}

void kpm_ctl_exit(void)
{
	misc_deregister(&kpm_ctl_dev);
	pr_info("kpm: ctl: device removed\n");
}