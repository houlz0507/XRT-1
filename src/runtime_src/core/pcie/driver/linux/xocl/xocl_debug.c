/**
 * Copyright (C) 2021 Xilinx, Inc. All rights reserved.
 *
 *  Thread to check sysmon/firewall status for errors/issues
 *  Author: Lizhi.Hou@Xilinx.com
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#include <linux/debugfs.h>
#include <linux/list.h>
#include "xocl_drv.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/clock.h>
#endif

char *xrt_debug_modules;
module_param(xrt_debug_modules, charp, (S_IRUGO|S_IWUSR));
MODULE_PARM_DESC(xrt_debug_modules, "Debug modules");

int xrt_debug_bufsize;
module_param(xrt_debug_bufsize, int, (S_IRUGO|S_IWUSR));
MODULE_PARM_DESC(xrt_debug_bufsize, "Debug buffer size");

#define MAX_TRACE_MSG_LEN	512
#define MAX_MOD_NAME		256

#define XOCL_DFS_TRACE		"trace"
#define XOCL_DFS_TRACE_MOD	"trace_modules"
#define XOCL_DFS_TRACE_CTRL	"trace_control"

enum {
	XOCL_DFS_TYPE_TRACE,
	XOCL_DFS_TYPE_COUNT,
};

struct xrt_debug_mod {
	/* do not move dev and arg */
	struct device		*dev;
	void			*arg;
	int (*enable_cb)(unsigned long hdl, bool enable);

	struct list_head	link;
	bool			enabled;
	char			name[MAX_MOD_NAME];
	int			mod_type;
	spinlock_t		lock;

	/* counter */
	ulong			count_addr_hi;
	ulong			count_addr_lo;
	u64			count_mask;
	u64			start_ts;
	bool			start_count;
	u64			count_period;
	u64			total_count;
};

struct xocl_debug {
	struct dentry		*debugfs_root;
	struct list_head	mod_list;
	struct mutex		mod_lock;

	/* global trace */
	spinlock_t		trace_lock;
	wait_queue_head_t	trace_wq;
	char			*trace_head;
	char			*read_head;
	bool			read_all;
	char			*buffer;
	u64			buffer_sz;
	char			*last_char;
	u64			overrun;
	char			extra_msg[MAX_TRACE_MSG_LEN];
};

static struct xocl_debug	xrt_debug = {
	.buffer_sz	= 4 * 1024 * 1024, /* 4M by default */
};

static int trace_open(struct inode *inode, struct file *file)
{
	spin_lock(&xrt_debug.trace_lock);
	xrt_debug.overrun = 0;
	xrt_debug.read_head = xrt_debug.trace_head;
	spin_unlock(&xrt_debug.trace_lock);

	return 0;
}	

static int trace_release(struct inode *inode, struct file *file)
{
	spin_lock(&xrt_debug.trace_lock);
	xrt_debug.read_all = false;
	spin_unlock(&xrt_debug.trace_lock);

	return 0;
}

static ssize_t trace_read(struct file *file, char __user *buf,
		size_t sz, loff_t *ppos)
{
	ssize_t count = 0;
	size_t len;

	if (wait_event_interruptible(xrt_debug.trace_wq, (!xrt_debug.read_all)) == -ERESTARTSYS)
		return -ERESTARTSYS;

	spin_lock(&xrt_debug.trace_lock);

	if (xrt_debug.overrun > 0) {
		pr_info("message overrun %lld\n", xrt_debug.overrun);
		xrt_debug.overrun = 0;
	}

	len = sz - count;
	if (!len)
		goto out;

	if (xrt_debug.read_head >= xrt_debug.trace_head) {
		len = min(len, (size_t)(xrt_debug.last_char - xrt_debug.read_head));
		if (len && copy_to_user(buf + count, xrt_debug.read_head, len) != 0) {
			count = -EFAULT;
			goto out;
		}
		count += len;
		xrt_debug.read_head += len;
		if (xrt_debug.read_head == xrt_debug.last_char)
			xrt_debug.read_head = xrt_debug.buffer;
	}

	len = sz - count;
	if (!len)
		goto out;

	if (xrt_debug.read_head < xrt_debug.trace_head) {
		len = min(len, (size_t)(xrt_debug.trace_head - xrt_debug.read_head));
		if (len && copy_to_user(buf + count, xrt_debug.read_head, len) != 0) {
			count = -EFAULT;
			goto out;
		}
		count += len;
		xrt_debug.read_head += len;
		if (xrt_debug.read_head == xrt_debug.trace_head)
			xrt_debug.read_all = true;
	}

out:
		
	spin_unlock(&xrt_debug.trace_lock);

	*ppos += count > 0 ? count : 0;

	return count;
}

static const struct file_operations trace_fops = {
	.owner = THIS_MODULE,
	.open = trace_open,
	.release = trace_release,
	.read = trace_read,
	.llseek = no_llseek,
};

static ssize_t trace_mod_read(struct file *file, char __user *buf,
		size_t sz, loff_t *ppos)
{
	struct xrt_debug_mod	*mod;
	ssize_t count = 0;
	loff_t offset = 0, len;
	char *temp;

	temp = vzalloc(MAX_TRACE_MSG_LEN);
	if (!temp)
		return -ENOMEM;

	mutex_lock(&xrt_debug.mod_lock);
	list_for_each_entry(mod, &xrt_debug.mod_list, link) {
		if (offset < *ppos) {
			offset++;
			continue;
		}

		if (sz - count < MAX_TRACE_MSG_LEN)
			break;

		len = 0;
		len += sprintf(temp, "%s\tenabled: %d", mod->name, mod->enabled);
		if (mod->mod_type == XOCL_DFS_TYPE_COUNT) {
			len += sprintf(temp + len, "\t %lld during %lld",
					mod->total_count, mod->count_period);
		}

		len += sprintf(temp + len, "\n");
		if (copy_to_user(buf + count, temp, strlen(temp)) != 0) {
			count = -EFAULT;
			break;
		}

		count += len;
		offset++;
	}

	mutex_unlock(&xrt_debug.mod_lock);
	vfree(temp);

	*ppos = offset;

	return count;
}

static const struct file_operations trace_mod_fops = {
	.owner = THIS_MODULE,
	.read = trace_mod_read,
};

static ssize_t trace_ctrl_write(struct file *filp, const char __user *data,
		size_t data_len, loff_t *ppos)
{
	struct xrt_debug_mod *mod = NULL, *_mod;
	ssize_t count = 0;
	char name[MAX_MOD_NAME];

	if (data_len > MAX_MOD_NAME)
		return -EINVAL;

	if (copy_from_user(name, data, data_len))
		return -EFAULT;

	mutex_lock(&xrt_debug.mod_lock);
	list_for_each_entry(_mod, &xrt_debug.mod_list, link) {
		if (strncmp(_mod->name, name, MAX_MOD_NAME))
			continue;

		if (mod) {
			mutex_lock(&xrt_debug.mod_lock);
			return -EINVAL;
		}

		mod = _mod;
	}

	if (mod->enable_cb && mod->enable_cb(mod, !mod->enabled)) {
		mutex_lock(&xrt_debug.mod_lock);
		return -EIO;
	}

	mod->enabled = !mod->enabled;

	if (mod->enabled && mod->mod_type == XOCL_DFS_TYPE_COUNT) {
		mod->total_count = 0;
		mod->count_period = 0;
	}

	mutex_lock(&xrt_debug.mod_lock);

	return 0;
}

static const struct file_operations trace_ctrl_fops = {
	.owner = THIS_MODULE,
	.write = trace_ctrl_write,
};

int xocl_debug_init(void)
{
	if (xrt_debug_bufsize > 0)
		xrt_debug.buffer_sz = xrt_debug_bufsize;

	xrt_debug.buffer = vzalloc(xrt_debug.buffer_sz);
	if (!xrt_debug.buffer)
		return -ENOMEM;
	xrt_debug.trace_head = xrt_debug.buffer;
	xrt_debug.read_head = xrt_debug.buffer;
	xrt_debug.last_char = xrt_debug.buffer;
	xrt_debug.read_all = true;

	xrt_debug.debugfs_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (IS_ERR(xrt_debug.debugfs_root)) {
		pr_info("creating debugfs root failed");
		return PTR_ERR(xrt_debug.debugfs_root);
	}

	debugfs_create_file(XOCL_DFS_TRACE, 0444,
		xrt_debug.debugfs_root, NULL, &trace_fops);

	debugfs_create_file(XOCL_DFS_TRACE_MOD, 0444,
		xrt_debug.debugfs_root, NULL, &trace_mod_fops);

	debugfs_create_file(XOCL_DFS_TRACE_CTRL, 0200,
		xrt_debug.debugfs_root, NULL, &trace_ctrl_fops);

	spin_lock_init(&xrt_debug.trace_lock);
	init_waitqueue_head(&xrt_debug.trace_wq);
	INIT_LIST_HEAD(&xrt_debug.mod_list);
	mutex_init(&xrt_debug.mod_lock);

	return 0;
}

void xocl_debug_fini(void)
{
	BUG_ON(!list_empty(&xrt_debug.mod_list));

	if (xrt_debug.buffer)
		vfree(xrt_debug.buffer);

	if (xrt_debug.debugfs_root)
		debugfs_remove_recursive(xrt_debug.debugfs_root);

	mutex_destroy(&xrt_debug.mod_lock);
}

int xocl_debug_unreg(unsigned long hdl)
{
	struct xrt_debug_mod	*mod, *temp;
	int ret = -ENOENT;

	mutex_lock(&xrt_debug.mod_lock);
	list_for_each_entry_safe(mod, temp, &xrt_debug.mod_list, link) {
		if ((unsigned long)mod != hdl)
			continue;

		ret = 0;
		list_del(&mod->link);
		kfree(mod);
	}
	mutex_unlock(&xrt_debug.mod_lock);

	if (ret)
		pr_err("not found");
	return ret;
}

int xocl_debug_register(struct xocl_dbg_reg *reg)
{
	struct xrt_debug_mod *mod, *tmp_mod;
	int ret = 0;

	reg->hdl = 0;
		
	if (!reg->name) {
		pr_err("invalid arguments");
		ret = -EINVAL;
		goto out;
	}

	mod = kzalloc(sizeof(*mod), GFP_KERNEL);
	if (!mod) {
		ret = -ENOMEM;
		goto out;
	}

	if (reg->dev) {
		snprintf(mod->name, sizeof(mod->name), "%s@%s",
			 reg->name, dev_name(PDEV(reg->dev)));
	} else {
		strncpy(mod->name, reg->name, sizeof(mod->name) - 1);
	}

	mutex_lock(&xrt_debug.mod_lock);
	list_for_each_entry(tmp_mod, &xrt_debug.mod_list, link) {
		if (!strncmp(tmp_mod->name, mod->name, sizeof(mod->name))) {
			pr_err("already registed");
			ret = -EEXIST;
			goto out;
		}
	}

	mod->dev = reg->dev;
	mod->enable_cb = reg->enable_cb;
	mod->arg = reg->arg;
	mod->count_addr_hi = reg->count_addr_hi;
	mod->count_addr_lo = reg->count_addr_lo;
	mod->count_mask = reg->count_mask;
	if (xrt_debug_modules && strstr(xrt_debug_modules, mod->name))
		mod->enabled = true;
	if (mod->count_mask)
		mod->mod_type = XOCL_DFS_TYPE_COUNT;
	spin_lock_init(&mod->lock);

	list_add(&mod->link, &xrt_debug.mod_list);
	reg->hdl = (unsigned long)mod;
out:
	mutex_unlock(&xrt_debug.mod_lock);

	return ret;
}

void xocl_dbg_count_start(unsigned long hdl)
{
	struct xrt_debug_mod *mod = (struct xrt_debug_mod *)hdl;

	if (!mod->enabled)
		return;


}

void xocl_dbg_count_stop(unsigned long hdl)
{
	struct xrt_debug_mod *mod = (struct xrt_debug_mod *)hdl;
}

void xocl_dbg_trace(unsigned long hdl, const char *fmt, ...)
{
	struct xrt_debug_mod *mod = (struct xrt_debug_mod *)hdl;
	struct va_format vaf;
	va_list args;
	unsigned long flags, nsec;
	char *endp;
	u64 ts;
	bool before = false;

	if (!mod->enabled)
		return;

	ts = local_clock();
	nsec = do_div(ts, 1000000000);

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;

	spin_lock_irqsave(&xrt_debug.trace_lock, flags);

	endp = xrt_debug.buffer + xrt_debug.buffer_sz;
	if (endp - xrt_debug.trace_head < MAX_TRACE_MSG_LEN) {
		xrt_debug.last_char = xrt_debug.trace_head;

		if (xrt_debug.trace_head <= xrt_debug.read_head)
			xrt_debug.read_head = xrt_debug.buffer;
		

		xrt_debug.trace_head = xrt_debug.buffer;
	}
	
	if (xrt_debug.trace_head < xrt_debug.read_head)
		before = true;

	xrt_debug.trace_head += snprintf(xrt_debug.trace_head, MAX_TRACE_MSG_LEN,
			"[%5lu.%06lu]%s: %pV", (unsigned long)ts, nsec / 1000,
			mod->name, &vaf);

	if (before && xrt_debug.trace_head >= xrt_debug.read_head) {
		xrt_debug.overrun += xrt_debug.trace_head - xrt_debug.read_head;
		xrt_debug.read_head = xrt_debug.trace_head;
	}

	if (xrt_debug.trace_head > xrt_debug.last_char)
		xrt_debug.last_char = xrt_debug.trace_head;

	xrt_debug.read_all = false;
	spin_unlock_irqrestore(&xrt_debug.trace_lock, flags);
	va_end(args);

	wake_up_interruptible(&xrt_debug.trace_wq);
}
