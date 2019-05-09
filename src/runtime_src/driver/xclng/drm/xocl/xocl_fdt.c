/*
 * Copyright (C) 2018 Xilinx, Inc. All rights reserved.
 *
 * Authors:
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/pci.h>
#include <linux/platform_device.h>
#include "xclfeatures.h"
#include "xocl_drv.h"
#include "version.h"

struct ip_node {
	const char *name;
	int level;
	int inst;
	u16 major;
	u16 minor;
};

static struct xocl_subdev_map		subdev_map[] = {
	{
		XOCL_SUBDEV_FEATURE_ROM,
		XOCL_FEATURE_ROM,
		{ "featurerom", NULL },
		1,
		0,
		NULL,
       	},
	{
		XOCL_SUBDEV_DMA,
		XOCL_XDMA,
		{ "xdma", NULL },
		1,
		0,
		NULL,
	},
	{
		XOCL_SUBDEV_DMA,
		XOCL_QDMA,
		{ "qdma", NULL },
		1,
		0,
		NULL,
       	},
	{
		XOCL_SUBDEV_MB_SCHEDULER,
		XOCL_MB_SCHEDULER,
		{ "ertsched", NULL },
		1,
		XOCL_SUBDEV_MAP_USERPF_ONLY,
		NULL,
       	},
	{
		XOCL_SUBDEV_XVC_PUB,
		XOCL_XVC_PUB,
		{ "axibscanuserprp", NULL },
		1,
		0,
	       	NULL,
       	},
	{
		XOCL_SUBDEV_XVC_PRI,
		XOCL_XVC_PRI,
		{ "axibscanmgmtbld", NULL },
		1,
		0,
	       	NULL,
       	},
	{
		XOCL_SUBDEV_SYSMON,
		XOCL_SYSMON,
		{ "sysmon", NULL },
		1,
		0,
		NULL,
       	},
	{
		XOCL_SUBDEV_AF,
		XOCL_FIREWALL,
		{
			"axifwhostctrlmgmt",
			"axifwdmactrlmgmt",
			"axifwdmactrluser",
			"axifwdmactrldebug",
			"axifwdmadata",
			"axirstn",
			NULL
		},
		1,
		0,
		NULL,
	},
	{
		XOCL_SUBDEV_MB,
		XOCL_MB,
		{
			"cmcregmapbram",
			"cmcmbrstctrl",
			"cmclmbbram",
			"cmcmbdmairq",
			NULL
		},
		1,
		0,
		NULL,
	},
	{
		XOCL_SUBDEV_MAILBOX,
		XOCL_MAILBOX,
		{ "pfmbox", NULL },
		1,
		0,
		NULL,
	},
	{
		XOCL_SUBDEV_ICAP_BLD,
		XOCL_ICAP_BLD,
		{
			"icap",
			"gateprbld",
			NULL
		},
		2,
		0,
		NULL,
	},
	{
		XOCL_SUBDEV_ICAP,
		XOCL_ICAP,
		{
			"icap",
			"memcalib",
			"gateprprp",
			"clkwizkernel1",
			"clkwizkernel2",
			NULL
		},
		5,
		0,
		NULL,
	},
	{
		XOCL_SUBDEV_XMC,
		XOCL_XMC,
		{
			"cmcregmapbram",
			"cmcmbctrl",
			"cmclmbbram",
			"ertlmbbram",
			"ertcqbram",
			NULL
		},
		1,
		0,
		NULL,
	},
#if 0
	{
		XOCL_SUBDEV_XIIC,
		XOCL_XIIC,
		(char *[]){ "cardi2c", NULL },
		NULL,
	},
#endif
};


/*
 * Functions to parse dtc and create sub devices
 */

static int overlay_apply_node(void *fdt, int target,
			      void *fdto, int node)
{
	int property;
	int subnode;

	fdt_for_each_property_offset(property, fdto, node) {
		const char *name;
		const void *prop;
		int prop_len;
		int ret;

		prop = fdt_getprop_by_offset(fdto, property, &name,
					     &prop_len);
		if (prop_len == -FDT_ERR_NOTFOUND)
			return -FDT_ERR_INTERNAL;
		if (prop_len < 0)
			return prop_len;

		ret = fdt_setprop(fdt, target, name, prop, prop_len);
		if (ret)
			return ret;
	}

	fdt_for_each_subnode(subnode, fdto, node) {
		const char *name = fdt_get_name(fdto, subnode, NULL);
		int nnode;
		int ret;

		nnode = fdt_add_subnode(fdt, target, name);
		if (nnode == -FDT_ERR_EXISTS) {
			nnode = fdt_subnode_offset(fdt, target, name);
			if (nnode == -FDT_ERR_NOTFOUND)
				return -FDT_ERR_INTERNAL;
		}

		if (nnode < 0)
			return nnode;

		ret = overlay_apply_node(fdt, nnode, fdto, subnode);
		if (ret)
			return ret;
	}

	return 0;
}

static int xocl_fdt_parse_seg(xdev_handle_t xdev_hdl, char *blob,
		int seg, struct ip_node *ip,
		struct xocl_subdev *subdevs, int dev_num)
{
	const char *name;
	int total = 0, idx, i, sz;
	const u32 *bar_idx, *pfnum;
	const u64 *io_off;
	const u16 *irq;
	for (seg = fdt_first_subnode(blob, seg); seg >= 0;
		seg = fdt_next_subnode(blob, seg)) {
		if (!subdevs) {
			total++;
			continue;
		}

		bar_idx = fdt_getprop(blob, seg, "BarMapping_u32", NULL);

		name = fdt_get_name(blob, seg, NULL);
		if (!name || !sscanf(name, "segment@%d", &idx)) {
			xocl_xdev_info(xdev_hdl,
				"IP %s, invalid segment %s",
				ip->name, name);
			return -EINVAL;
		}
		name = fdt_getprop(blob, seg, "Name_sz", NULL);
		if (!name)
			name = "";

		/* Get PF index */
		pfnum = fdt_getprop(blob, seg, "PFMapping_u32", NULL);
		if (!pfnum) {
			xocl_xdev_info(xdev_hdl,
				"IP %s, PF index not found", ip->name);
			return -EINVAL;
		}

		for (i = 0; i < dev_num; i++) {
			if (!subdevs[i].info.dyn_ip) {
				subdevs[i].info.level = ip->level;
				subdevs[i].pf = ntohl(*pfnum);
				subdevs[i].info.bar_idx =
					bar_idx ? ntohl(*bar_idx) : 0;
				subdevs[i].info.dyn_ip++;
				total++;
				break;
			} else if (subdevs[i].info.level == ip->level &&
				    subdevs[i].pf == ntohl(*pfnum)) {
				subdevs[i].info.dyn_ip++;
				total++;
				break;
			}
		}
		xocl_xdev_info(xdev_hdl, "ipname %s, %s, %d/%d",
			     ip->name, name, i, dev_num);
		if (i == dev_num)
			continue;

		io_off = fdt_getprop(blob, seg, "OffsetRange_au64", &sz);
		while (io_off && sz >= sizeof(*io_off) * 2) {
			idx = subdevs[i].info.num_res;
			subdevs[i].res[idx].start = be64_to_cpu(io_off[0]);
			subdevs[i].res[idx].end = subdevs[i].res[idx].start +
			       be64_to_cpu(io_off[1]) - 1;
			subdevs[i].res[idx].flags = IORESOURCE_MEM;
			snprintf(subdevs[i].res_name[idx],
				XOCL_SUBDEV_RES_NAME_LEN,
				"%s/%s.%d.%d.%d",
				ip->name, name, ip->major, ip->minor,
				ip->level);
			subdevs[i].res[idx].name = subdevs[i].res_name[idx];

			subdevs[i].info.num_res++;
			sz -= sizeof(*io_off) * 2;
			io_off += 2;
		}

		irq = fdt_getprop(blob, seg, "IRQRanges_au16", &sz);
		while (irq && sz >= sizeof(*irq) * 2) {
			idx = subdevs[i].info.num_res;
			subdevs[i].res[idx].start = ntohs(irq[0]);
			subdevs[i].res[idx].end = ntohs(irq[1]);
			subdevs[i].res[idx].flags = IORESOURCE_IRQ;
			snprintf(subdevs[i].res_name[idx],
				XOCL_SUBDEV_RES_NAME_LEN,
				"%s/%s.%d.%d.%d",
				ip->name, name, ip->major, ip->minor,
				ip->level);
			subdevs[i].res[idx].name = subdevs[i].res_name[idx];
					subdevs[i].info.num_res++;
					sz -= sizeof(*irq) * 2;
					irq += 2;
		}

	}

	return total;
}

static int xocl_fdt_next_ip(xdev_handle_t xdev_hdl, char *blob,
		int off, struct ip_node *ip)
{
	char *l0_path = "/_self_/ips";
	char *l1_path = "/exposes/regions/level1_prp/ips";
	int l1_off, l0_off, node, end;
	const u16 *ver;

	l0_off = fdt_path_offset(blob, l0_path);
	if (l0_off < 0) {
		xocl_xdev_err(xdev_hdl, "Did not find l0 devices");
		return -ENODEV;
	}

	if (off == 0) {
		ip->level = XOCL_SUBDEV_LEVEL_BLD;
		node = fdt_first_subnode(blob, l0_off);
		goto found;
	}

	end = fdt_next_subnode(blob, l0_off);
	if (end < 0 || off < end) {
		node = fdt_next_subnode(blob, off);
		if (node > 0) {
			ip->level = XOCL_SUBDEV_LEVEL_BLD;
			goto found;
		}
	}
	
	l1_off = fdt_path_offset(blob, l1_path);
	if (l1_off < 0)
		return -ENODEV;

	if (off < l1_off) {
		ip->level = XOCL_SUBDEV_LEVEL_PRP;
		node = fdt_first_subnode(blob, l1_off);
		goto found;
	}

	node = fdt_next_subnode(blob, off);
	if (node > 0) {
		ip->level = XOCL_SUBDEV_LEVEL_PRP;
		goto found;
	}

	return -ENODEV;

found:
	ip->name = fdt_get_name(blob, node, NULL);

	/* Get Version */
	ver = fdt_getprop(blob, node, "Version_au16", NULL);
	ip->major = ntohs(ver[0]);
	ip->minor = ntohs(ver[1]);

	return node;
}

static int xocl_fdt_ip_lookup(xdev_handle_t xdev_hdl, char *blob,
		const char *ipname,
		struct xocl_subdev *subdevs, int dev_num)
{
	struct ip_node	ip;
	int off = 0, seg, num, total = 0; 

	for (off = xocl_fdt_next_ip(xdev_hdl, blob, off, &ip); off >= 0;
		off = xocl_fdt_next_ip(xdev_hdl, blob, off, &ip)) {

		if (!ip.name || strncmp(ip.name, ipname, strlen(ipname)))
			continue;

		/* go through all segments */
		seg = fdt_subnode_offset(blob, off, "segments");
		if (seg < 0)
			continue;

		num = xocl_fdt_parse_seg(xdev_hdl, blob, seg, &ip,
				subdevs, dev_num);
		if (num < 0) {
			xocl_xdev_err(xdev_hdl,
					"parse ip failed, Node %s, ip %s",
					ip.name, ipname);
			return num;
		}
		total += num;
	}

	return total;
}

static void xocl_fdt_dump_subdev(xdev_handle_t xdev_hdl,
		struct xocl_subdev *subdev)
{
	int i;

	xocl_xdev_info(xdev_hdl, "Device %s, PF%d, level %d",
		subdev->info.name, subdev->pf, subdev->info.level);

	for (i = 0; i < subdev->info.num_res; i++)
		xocl_xdev_info(xdev_hdl, "Res%d: %s %pR", i,
			subdev->info.res[i].name, &subdev->info.res[i]);
}

static int xocl_fdt_get_devinfo(xdev_handle_t xdev_hdl, char *blob,
		struct xocl_subdev_map  *map_p,
		struct xocl_subdev *rtn_subdevs)
{
	struct xocl_subdev *subdevs = NULL;
	char *ip;
	int dev_num = 0, ip_num, sz = 0, i;

	for (ip_num = 0, ip = map_p->ip_names[0]; ip;
			ip = map_p->ip_names[++ip_num]) {
		dev_num = xocl_fdt_ip_lookup(xdev_hdl, blob, ip,
					subdevs, dev_num);
		if (dev_num < 0) {
			xocl_xdev_err(xdev_hdl, "lookup dev %s, ip %s failed",
					map_p->dev_name, ip);
			goto failed;
		} else if (dev_num == 0)
			break;

		if (!subdevs) {
			subdevs = vzalloc(sizeof(*subdevs) * dev_num);
			sz = dev_num;
			ip_num--;
		}
	}

	dev_num = 0;
	for (i = 0; i < sz; i++) {
		if ((map_p->flags & XOCL_SUBDEV_MAP_USERPF_ONLY) &&
			subdevs[i].pf == XOCL_PCI_FUNC(xdev_hdl))
			continue;
		if (subdevs[i].info.dyn_ip >= map_p->required_ip) {
			subdevs[i].info.id = map_p->id;
			subdevs[i].info.name = map_p->dev_name;
			memcpy(&rtn_subdevs[dev_num], &subdevs[i],
					sizeof(struct xocl_subdev));
			rtn_subdevs[dev_num].info.res =
				rtn_subdevs[dev_num].res;
			rtn_subdevs[dev_num].info.res =
				rtn_subdevs[dev_num].res;
			for (ip_num = 0;
				ip_num < rtn_subdevs[dev_num].info.num_res;
				ip_num ++)
				rtn_subdevs[dev_num].info.res[ip_num].name =
					rtn_subdevs[dev_num].res_name[ip_num];
			xocl_fdt_dump_subdev(xdev_hdl, &rtn_subdevs[dev_num]);
			dev_num++;
		}
	}

failed:
	if (subdevs) {
		vfree(subdevs);
	}
	return dev_num;
}

static int xocl_fdt_parse_subdevs(xdev_handle_t xdev_hdl, char *blob,
		struct xocl_subdev *subdevs)
{
	struct xocl_subdev_map  *map_p;
	int id, j, num, total = 0;

	for (id = 0; id < XOCL_SUBDEV_NUM; id++) { 
		for (j = 0; j < ARRAY_SIZE(subdev_map); j++) {
			map_p = &subdev_map[j];
			if (map_p->id != id)
				continue;

			num = xocl_fdt_get_devinfo(xdev_hdl, blob, map_p,
					subdevs + total);
			if (num < 0) {
				xocl_xdev_err(xdev_hdl,
					"get subdev info failed, dev name: %s",
					map_p->dev_name);
				return num;
			}

			total += num;
		}
	}

	return total;
}

static int xocl_fdt_parse_blob(xdev_handle_t xdev_hdl, char *blob,
		struct xocl_subdev *subdevs)
{
	int		dev_num; 

	dev_num = xocl_fdt_parse_subdevs(xdev_hdl, blob, subdevs);
	if (dev_num < 0) {
		xocl_xdev_err(xdev_hdl, "parse dev failed, ret = %d", dev_num);
		goto failed;
	}

failed:
	return dev_num;
}

int xocl_fdt_blob_input(xdev_handle_t xdev_hdl, char *blob, size_t len,
		struct xocl_subdev *subdevs, int *subdev_num)
{
	struct xocl_dev_core	*core = XDEV(xdev_hdl);
	char			*input_blob;
	int			ret;

	input_blob = vmalloc(XOCL_MAX_FDT_LEN);
	if (!input_blob)
		return -ENOMEM;

	ret = fdt_create_empty_tree(input_blob, XOCL_MAX_FDT_LEN);
	if (ret) {
		xocl_xdev_err(xdev_hdl, "create input blob failed %d", ret);
		goto failed;
	}
	overlay_apply_node(input_blob, 0, blob, 0);
	if (ret) {
		xocl_xdev_err(xdev_hdl, "overlay input blob failed %d", ret);
		goto failed;
	}

	if (!core->fdt_blob) {
		//memcpy(core->fdt_blob, blob, len);
		core->fdt_blob = vmalloc(XOCL_MAX_FDT_LEN);
		if (!core->fdt_blob) {
			ret = -ENOMEM;
			goto failed;
		}

		ret = fdt_create_empty_tree(core->fdt_blob, XOCL_MAX_FDT_LEN);
		if (ret) {
			xocl_xdev_err(xdev_hdl, "create fdt failed %d", ret);
			goto failed;
		}
	}

	ret = overlay_apply_node(core->fdt_blob, 0, input_blob, 0);
	if (ret) {
		xocl_xdev_err(xdev_hdl, "Overlay blob failed %d", ret);
		goto failed;
	}

	vfree(input_blob);

	ret = xocl_fdt_parse_blob(xdev_hdl, core->fdt_blob, subdevs);
	if (ret < 0)
		goto failed;
	*subdev_num = ret;

	return 0;

failed:
	vfree(input_blob);
	return ret;
}
