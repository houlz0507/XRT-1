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

#define MAX_TRACE_MSG_LEN	512
#define XOCL_DEBUGFS_LOGFILE	"trace"

struct xrt_debug_mod {
	struct list_head	link;
	struct device		*dev;
	const char		*name;
};

struct xocl_debug {
	struct dentry		*debugfs_root;
	struct list_head	mod_list;
	struct mutex		mod_lock;

	/* global trace */
	spinlock_t		trace_lock;
	char			*trace_head;
	char			*read_head;
	char			*buffer;
	u64			buffer_sz;
};

static struct xocl_debug	xrt_debug = {
	.buffer_sz	= 4 * 1024 * 1024, /* 4M by default */
};

static int trace_open(struct inode *inode, struct file *file)
{
	return 0;
}	

static int trace_release(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t trace_read(struct file *file, char __user *buf,
		size_t sz, loff_t *ppos)
{
	return 0;
}

static const struct file_operations trace_fops = {
	.owner = THIS_MODULE,
	.open = trace_open,
	.release = trace_release,
	.read = trace_read,
	.llseek = no_llseek,
};

int xocl_debug_init(void)
{
	xrt_debug.buffer = vzalloc(xrt_debug.buffer_sz);
	if (!xrt_debug.buffer)
		return -ENOMEM;
	xrt_debug.trace_head = xrt_debug.buffer;
	xrt_debug.read_head = xrt_debug.buffer;

	xrt_debug.debugfs_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (IS_ERR(xrt_debug.debugfs_root)) {
		pr_info("creating debugfs root failed");
		return PTR_ERR(xrt_debug.debugfs_root);
	}

	debugfs_create_file(XOCL_DEBUGFS_LOGFILE, 0444,
		xrt_debug.debugfs_root, NULL, &trace_fops);

	spin_lock_init(&xrt_debug.trace_lock);
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

int xocl_debug_unreg(struct device *dev)
{
	struct xrt_debug_mod	*mod, *temp;
	int ret = -ENOENT;

	mutex_lock(&xrt_debug.mod_lock);
	list_for_each_entry_safe(mod, temp, &xrt_debug.mod_list, link) {
		if (mod->dev != dev)
			continue;

		ret = 0;
		list_del(&mod->link);
		kfree(mod);
	}
	mutex_unlock(&xrt_debug.mod_lock);

	return ret;
}

int xocl_debug_register(struct device *dev, const char *name, unsigned long *hdl)
{
	struct xrt_debug_mod	*mod;
	int ret = 0;

	*hdl = 0;
	mutex_lock(&xrt_debug.mod_lock);
	list_for_each_entry(mod, &xrt_debug.mod_list, link) {
		if (mod->dev == dev) {
			xocl_err(dev, "already registed");
			ret = -EEXIST;
			goto out;
		}
	}

	mod = kzalloc(sizeof(*mod), GFP_KERNEL);
	if (!mod) {
		ret = -ENOMEM;
		goto out;
	}

	mod->name = name ? name : dev_name(dev);
	mod->dev = dev;

	list_add(&mod->link, &xrt_debug.mod_list);
	*hdl = (unsigned long)mod;
out:
	mutex_unlock(&xrt_debug.mod_lock);

	return ret;
}

void xocl_trace(unsigned long hdl, const char *fmt, ...)
{
	struct xrt_debug_mod *mod = (struct xrt_debug_mod *)hdl;
	struct va_format vaf;
	va_list args;
	unsigned long flags, nsec;
	char *endp;
	u64 ts;

	ts = local_clock();
	nsec = do_div(ts, 1000000000);

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;

	spin_lock_irqsave(&xrt_debug.trace_lock, flags);

	endp = xrt_debug.buffer + xrt_debug.buffer_sz;
	if (endp - xrt_debug.trace_head < MAX_TRACE_MSG_LEN) {
		if (xrt_debug.trace_head < endp) 
			*xrt_debug.trace_head = 0;
		xrt_debug.trace_head = xrt_debug.buffer;
	}

	xrt_debug.trace_head += snprintf(xrt_debug.trace_head, MAX_TRACE_MSG_LEN,
			"[%5lu.%06lu]%s: %pV", (unsigned long)ts, nsec / 1000,
			mod->name ? mod->name : dev_name(mod->dev), &vaf);

	spin_unlock_irqrestore(&xrt_debug.trace_lock, flags);
	va_end(args);
}
