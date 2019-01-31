/**
 *  Copyright (C) 2017 Xilinx, Inc. All rights reserved.
 *  Author: Sonal Santan
 *  Code copied verbatim from SDAccel xcldma kernel mode driver
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

/*
 * TODO: Currently, locking / unlocking bitstream is implemented w/ pid as
 * identification of bitstream users. We assume that, on bare metal, an app
 * has only one process and will open both user and mgmt pfs. In this model,
 * xclmgmt has enough information to handle locking/unlocking alone, but we
 * still involve user pf and mailbox here so that it'll be easier to support
 * cloud env later. We'll replace pid with a token that is more appropriate
 * to identify a user later as well.
 */

#include <linux/firmware.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/uuid.h>
#include <linux/pid.h>
#include "xclbin.h"
#include "../xocl_drv.h"
#include "mgmt-ioctl.h"

#if defined(XOCL_UUID)
static xuid_t uuid_null = NULL_UUID_LE;
#endif

#define	ICAP_ERR(icap, fmt, arg...)	\
	xocl_err(&(icap)->icap_pdev->dev, fmt "\n", ##arg)
#define	ICAP_INFO(icap, fmt, arg...)	\
	xocl_info(&(icap)->icap_pdev->dev, fmt "\n", ##arg)
#define	ICAP_DBG(icap, fmt, arg...)	\
	xocl_dbg(&(icap)->icap_pdev->dev, fmt "\n", ##arg)

#define	ICAP_PRIVILEGED(icap)	((icap)->icap_regs != NULL)
#define DMA_HWICAP_BITFILE_BUFFER_SIZE 1024
#define	ICAP_MAX_REG_GROUPS		ARRAY_SIZE(XOCL_RES_ICAP_MGMT)

#define	ICAP_MAX_NUM_CLOCKS		2
#define OCL_CLKWIZ_STATUS_OFFSET	0x4
#define OCL_CLKWIZ_CONFIG_OFFSET(n)	(0x200 + 4 * (n))
#define OCL_CLK_FREQ_COUNTER_OFFSET	0x8
#define	ICAP_XCLBIN_V2			"xclbin2"

/*
 * Bitstream header information.
 */
typedef struct {
	unsigned int HeaderLength;     /* Length of header in 32 bit words */
	unsigned int BitstreamLength;  /* Length of bitstream to read in bytes*/
	unsigned char *DesignName;     /* Design name read from bitstream header */
	unsigned char *PartName;       /* Part name read from bitstream header */
	unsigned char *Date;           /* Date read from bitstream header */
	unsigned char *Time;           /* Bitstream creation time read from header */
	unsigned int MagicLength;      /* Length of the magic numbers in header */
} XHwIcap_Bit_Header;
#define XHI_BIT_HEADER_FAILURE 	-1
/* Used for parsing bitstream header */
#define XHI_EVEN_MAGIC_BYTE	0x0f
#define XHI_ODD_MAGIC_BYTE	0xf0
/* Extra mode for IDLE */
#define XHI_OP_IDLE		-1
/* The imaginary module length register */
#define XHI_MLR			15

#define	GATE_FREEZE_USER	0x0c
#define GATE_FREEZE_SHELL	0x00

#define GATE_FREE_STEPS		4
static u32 gate_free_user[GATE_FREE_STEPS] = {0xe, 0xc, 0xe, 0xf};
static u32 gate_free_shell[GATE_FREE_STEPS] = {0x8, 0xc, 0xe, 0xf};

/*
 * AXI-HWICAP IP register layout
 */
struct icap_reg {
	u32			ir_rsvd1[7];
	u32			ir_gier;
	u32			ir_isr;
	u32			ir_rsvd2;
	u32			ir_ier;
	u32			ir_rsvd3[53];
	u32			ir_wf;
	u32			ir_rf;
	u32			ir_sz;
	u32			ir_cr;
	u32			ir_sr;
	u32			ir_wfv;
	u32			ir_rfo;
	u32			ir_asr;
} __attribute__((packed));

struct icap_generic_state {
	u32			igs_state;
} __attribute__((packed));

struct icap_axi_gate {
	u32			iag_wr;
	u32			iag_rvsd;
	u32			iag_rd;
} __attribute__((packed));

struct icap_bitstream_user {
	struct list_head	ibu_list;
	pid_t			ibu_pid;
};

struct icap {
	struct platform_device	*icap_pdev;
	struct mutex		icap_lock;
	struct icap_reg		*icap_regs;
	struct icap_generic_state *icap_state;
	unsigned int            idcode;
	bool			icap_axi_gate_frozen;
	struct icap_axi_gate	*icap_axi_gate;

	u64			icap_bitstream_id;
	xuid_t			icap_bitstream_uuid;
	int			icap_bitstream_ref;
	struct list_head	icap_bitstream_users;

	char			*icap_clear_bitstream;
	unsigned long		icap_clear_bitstream_length;

	char			*icap_clock_bases[ICAP_MAX_NUM_CLOCKS];
	unsigned short		icap_ocl_frequency[ICAP_MAX_NUM_CLOCKS];

	char                    *icap_clock_freq_topology;
	unsigned long		icap_clock_freq_topology_length;
	char                    *icap_clock_freq_counter;
	struct mem_topology      *mem_topo;
	struct ip_layout         *ip_layout;
	struct debug_ip_layout   *debug_layout;
	struct connectivity      *connectivity;

#ifdef SYSFS_DEBUG
	char			*bit_buffer;
	unsigned long		bit_length;
#endif
};

static inline u32 reg_rd(void __iomem *reg)
{
	return XOCL_READ_REG32(reg);
}

static inline void reg_wr(void __iomem *reg, u32 val)
{
	iowrite32(val, reg);
}

/*
 * Precomputed table with config0 and config2 register values together with
 * target frequency. The steps are approximately 5 MHz apart. Table is
 * generated by wiz.pl.
 */
const static struct xclmgmt_ocl_clockwiz {
	/* target frequency */
	unsigned short ocl;
	/* config0 register */
	unsigned long config0;
	/* config2 register */
	unsigned short config2;
} frequency_table[] = {
	{/* 600*/   60, 0x0601, 0x000a},
	{/* 600*/   66, 0x0601, 0x0009},
	{/* 600*/   75, 0x0601, 0x0008},
	{/* 800*/   80, 0x0801, 0x000a},
	{/* 600*/   85, 0x0601, 0x0007},
	{/* 900*/   90, 0x0901, 0x000a},
	{/*1000*/  100, 0x0a01, 0x000a},
	{/*1100*/  110, 0x0b01, 0x000a},
	{/* 700*/  116, 0x0701, 0x0006},
	{/*1100*/  122, 0x0b01, 0x0009},
	{/* 900*/  128, 0x0901, 0x0007},
	{/*1200*/  133, 0x0c01, 0x0009},
	{/*1400*/  140, 0x0e01, 0x000a},
	{/*1200*/  150, 0x0c01, 0x0008},
	{/*1400*/  155, 0x0e01, 0x0009},
	{/* 800*/  160, 0x0801, 0x0005},
	{/*1000*/  166, 0x0a01, 0x0006},
	{/*1200*/  171, 0x0c01, 0x0007},
	{/* 900*/  180, 0x0901, 0x0005},
	{/*1300*/  185, 0x0d01, 0x0007},
	{/*1400*/  200, 0x0e01, 0x0007},
	{/*1300*/  216, 0x0d01, 0x0006},
	{/* 900*/  225, 0x0901, 0x0004},
	{/*1400*/  233, 0x0e01, 0x0006},
	{/*1200*/  240, 0x0c01, 0x0005},
	{/*1000*/  250, 0x0a01, 0x0004},
	{/*1300*/  260, 0x0d01, 0x0005},
	{/* 800*/  266, 0x0801, 0x0003},
	{/*1100*/  275, 0x0b01, 0x0004},
	{/*1400*/  280, 0x0e01, 0x0005},
	{/*1200*/  300, 0x0c01, 0x0004},
	{/*1300*/  325, 0x0d01, 0x0004},
	{/*1000*/  333, 0x0a01, 0x0003},
	{/*1400*/  350, 0x0e01, 0x0004},
	{/*1100*/  366, 0x0b01, 0x0003},
	{/*1200*/  400, 0x0c01, 0x0003},
	{/*1300*/  433, 0x0d01, 0x0003},
	{/* 900*/  450, 0x0901, 0x0002},
	{/*1400*/  466, 0x0e01, 0x0003},
	{/*1000*/  500, 0x0a01, 0x0002}
};

static struct icap_bitstream_user *alloc_user(pid_t pid)
{
	struct icap_bitstream_user *u =
		kzalloc(sizeof(struct icap_bitstream_user), GFP_KERNEL);

	if (u) {
		INIT_LIST_HEAD(&u->ibu_list);
		u->ibu_pid = pid;
	}
	return u;
}

static void free_user(struct icap_bitstream_user *u)
{
	kfree(u);
}

static struct icap_bitstream_user *obtain_user(struct icap *icap, pid_t pid)
{
	struct list_head *pos, *n;

	list_for_each_safe(pos, n, &icap->icap_bitstream_users) {
		struct icap_bitstream_user *u = list_entry(pos, struct icap_bitstream_user, ibu_list);
		if (u->ibu_pid == pid)
			return u;
	}

	return NULL;
}

static int add_user(struct icap *icap, pid_t pid)
{
	struct icap_bitstream_user *u;

	u = obtain_user(icap, pid);
	if (u)
		return 0;

	u = alloc_user(pid);
	if (!u)
		return -ENOMEM;

	list_add_tail(&u->ibu_list, &icap->icap_bitstream_users);
	icap->icap_bitstream_ref++;
	return 0;
}

static int del_user(struct icap *icap, pid_t pid)
{
	struct icap_bitstream_user *u = NULL;

	u = obtain_user(icap, pid);
	if (!u)
		return -EINVAL;

	list_del(&u->ibu_list);
	free_user(u);
	icap->icap_bitstream_ref--;
	return 0;
}

static void del_all_users(struct icap *icap)
{
	struct icap_bitstream_user *u = NULL;
	struct list_head *pos, *n;

	if (icap->icap_bitstream_ref == 0)
		return;

	list_for_each_safe(pos, n, &icap->icap_bitstream_users) {
		u = list_entry(pos, struct icap_bitstream_user, ibu_list);
		list_del(&u->ibu_list);
		free_user(u);
	}

	ICAP_INFO(icap, "removed %d users", icap->icap_bitstream_ref);
	icap->icap_bitstream_ref = 0;
}

static unsigned find_matching_freq_config(unsigned freq)
{
	unsigned start = 0;
	unsigned end = ARRAY_SIZE(frequency_table) - 1;
	unsigned idx = ARRAY_SIZE(frequency_table) - 1;

	if (freq < frequency_table[0].ocl)
		return 0;

	if (freq > frequency_table[ARRAY_SIZE(frequency_table) - 1].ocl)
		return ARRAY_SIZE(frequency_table) - 1;

	while (start < end) {
		if (freq == frequency_table[idx].ocl)
			break;
		if (freq < frequency_table[idx].ocl)
			end = idx;
		else
			start = idx + 1;
		idx = start + (end - start) / 2;
	}
	if (freq < frequency_table[idx].ocl)
		idx--;

	return idx;
}

static unsigned short icap_get_ocl_frequency(const struct icap *icap, int idx)
{
#define XCL_INPUT_FREQ 100
	const u64 input = XCL_INPUT_FREQ;
	u32 val;
	u32 mul0, div0;
	u32 mul_frac0 = 0;
	u32 div1;
	u32 div_frac1 = 0;
	u64 freq;
	char *base = icap->icap_clock_bases[idx];

        val = reg_rd(base + OCL_CLKWIZ_STATUS_OFFSET);
	if ((val & 1) == 0)
		return 0;

	val = reg_rd(base + OCL_CLKWIZ_CONFIG_OFFSET(0));

	div0 = val & 0xff;
	mul0 = (val & 0xff00) >> 8;
	if (val & BIT(26)) {
		mul_frac0 = val >> 16;
		mul_frac0 &= 0x3ff;
	}

	/*
	 * Multiply both numerator (mul0) and the denominator (div0) with 1000
	 * to account for fractional portion of multiplier
	 */
	mul0 *= 1000;
	mul0 += mul_frac0;
	div0 *= 1000;

	val = reg_rd(base + OCL_CLKWIZ_CONFIG_OFFSET(2));

	div1 = val &0xff;
	if (val & BIT(18)) {
		div_frac1 = val >> 8;
		div_frac1 &= 0x3ff;
	}

	/*
	 * Multiply both numerator (mul0) and the denominator (div1) with 1000 to
	 * account for fractional portion of divider
	 */

	div1 *= 1000;
	div1 += div_frac1;
	div0 *= div1;
	mul0 *= 1000;
	if (div0 == 0) {
		ICAP_ERR(icap, "clockwiz 0 divider");
		return 0;
	}

	freq = (input * mul0) / div0;
	return freq;
}

static unsigned int icap_get_clock_frequency_counter_khz(const struct icap *icap, int idx)
{
	u32 freq, status;
	char *base = icap->icap_clock_freq_counter;
	int times;
	times = 10;
	freq = 0;
	/*
	 * reset and wait until done
	 */

	if(uuid_is_null(&icap->icap_bitstream_uuid)){
		ICAP_ERR(icap, "ERROR: There isn't a xclbin loaded in the dynamic region."
			"frequencies counter cannot be determine");
		return freq;
	}
	reg_wr(base, 0x1);

	while(times!=0){
		status = reg_rd(base);
		if(status==0x2)
			break;
		mdelay(1);
		times--;
	};

  freq = reg_rd(base + OCL_CLK_FREQ_COUNTER_OFFSET + idx*sizeof(u32));

  return freq;
}
/*
 * Based on Clocking Wizard v5.1, section Dynamic Reconfiguration
 * through AXI4-Lite
 */
static int icap_ocl_freqscaling(struct icap *icap, bool force)
{
	unsigned curr_freq;
	u32 config;
	int i;
	int j = 0;
	u32 val = 0;
	unsigned idx = 0;
	long err = 0;

	for(i = 0; i < ICAP_MAX_NUM_CLOCKS; ++i) {
		// A value of zero means skip scaling for this clock index
		if (!icap->icap_ocl_frequency[i])
			continue;

		idx = find_matching_freq_config(icap->icap_ocl_frequency[i]);
		curr_freq = icap_get_ocl_frequency(icap, i);

		/*
		 * If current frequency is in the same step as the
		 * requested frequency then nothing to do.
		 */
		if (!force && (find_matching_freq_config(curr_freq) == idx))
			continue;

		val = reg_rd(icap->icap_clock_bases[i] +
			OCL_CLKWIZ_STATUS_OFFSET);
		if (val != 1) {
			ICAP_ERR(icap, "clockwiz %d is busy", i);
			err = -EBUSY;
			break;;
		}

		config = frequency_table[idx].config0;
		reg_wr(icap->icap_clock_bases[i] + OCL_CLKWIZ_CONFIG_OFFSET(0),
			config);
		config = frequency_table[idx].config2;
		reg_wr(icap->icap_clock_bases[i] + OCL_CLKWIZ_CONFIG_OFFSET(2),
			config);
		msleep(10);
		reg_wr(icap->icap_clock_bases[i] + OCL_CLKWIZ_CONFIG_OFFSET(23),
			0x00000007);
		msleep(1);
		reg_wr(icap->icap_clock_bases[i] + OCL_CLKWIZ_CONFIG_OFFSET(23),
			0x00000002);

		ICAP_INFO(icap, "clockwiz waiting for locked signal");
		msleep(100);
		for (j = 0; j < 100; j++) {
			val = reg_rd(icap->icap_clock_bases[i] +
				OCL_CLKWIZ_STATUS_OFFSET);
			if (val != 1) {
				msleep(100);
				continue;
			}
		}
		if (val != 1) {
			ICAP_ERR(icap, "clockwiz MMCM/PLL did not lock after %d"
				"ms, restoring the original configuration",
				100 * 100);
			/* restore the original clock configuration */
			reg_wr(icap->icap_clock_bases[i] +
				OCL_CLKWIZ_CONFIG_OFFSET(23), 0x00000004);
			msleep(10);
			reg_wr(icap->icap_clock_bases[i] +
				OCL_CLKWIZ_CONFIG_OFFSET(23), 0x00000000);
			err = -ETIMEDOUT;
			break;
		}
		val = reg_rd(icap->icap_clock_bases[i] +
			OCL_CLKWIZ_CONFIG_OFFSET(0));
		ICAP_INFO(icap, "clockwiz CONFIG(0) 0x%x", val);
		val = reg_rd(icap->icap_clock_bases[i] +
			OCL_CLKWIZ_CONFIG_OFFSET(2));
		ICAP_INFO(icap, "clockwiz CONFIG(2) 0x%x", val);
	}

	return err;
}

static bool icap_bitstream_in_use(struct icap *icap, pid_t pid)
{
	BUG_ON(icap->icap_bitstream_ref < 0);

	/* Any user counts if pid isn't specified. */
	if (pid == 0)
		return icap->icap_bitstream_ref != 0;

	if (icap->icap_bitstream_ref == 0)
		return false;
	if ((icap->icap_bitstream_ref == 1) && obtain_user(icap, pid))
		return false;
	return true;
}

static int icap_freeze_axi_gate(struct icap *icap, u32 val)
{
	xdev_handle_t xdev = xocl_get_xdev(icap->icap_pdev);

	ICAP_INFO(icap, "freezing AXI gate");
	BUG_ON(icap->icap_axi_gate_frozen);

	(void) reg_rd(&icap->icap_axi_gate->iag_rd);
	reg_wr(&icap->icap_axi_gate->iag_wr, val);
	(void) reg_rd(&icap->icap_axi_gate->iag_rd);

	if(!xocl_is_unified(xdev)) {
		reg_wr(&icap->icap_regs->ir_cr, 0xc);
		ndelay(20);
	} else {
		/* New ICAP reset sequence applicable only to unified dsa. */
		reg_wr(&icap->icap_regs->ir_cr, 0x8);
		ndelay(2000);
		reg_wr(&icap->icap_regs->ir_cr, 0x0);
		ndelay(2000);
		reg_wr(&icap->icap_regs->ir_cr, 0x4);
		ndelay(2000);
		reg_wr(&icap->icap_regs->ir_cr, 0x0);
		ndelay(2000);
	}

	icap->icap_axi_gate_frozen = true;

	return 0;
}

static int icap_free_axi_gate(struct icap *icap, u32 *vals)
{
	int i;

	ICAP_INFO(icap, "freeing AXI gate");
	/*
	 * First pulse the OCL RESET. This is important for PR with multiple
	 * clocks as it resets the edge triggered clock converter FIFO
	 */

	if (!icap->icap_axi_gate_frozen)
		return 0;


	for (i = 0; i < GATE_FREE_STEPS; i++) {
		(void) reg_rd(&icap->icap_axi_gate->iag_rd);
		reg_wr(&icap->icap_axi_gate->iag_wr, vals[i]);
		mdelay(50);
	}

	(void) reg_rd(&icap->icap_axi_gate->iag_rd);

	icap->icap_axi_gate_frozen = false;

	return 0;
}

static void platform_reset_axi_gate(struct platform_device *pdev)
{
	struct icap *icap = platform_get_drvdata(pdev);

	/* Can only be done from mgmt pf. */
	if (!ICAP_PRIVILEGED(icap))
		return;

	mutex_lock(&icap->icap_lock);
	if (!icap_bitstream_in_use(icap, 0)) {
		(void) icap_freeze_axi_gate(platform_get_drvdata(pdev),
			GATE_FREEZE_USER);
		msleep(500);
		(void) icap_free_axi_gate(platform_get_drvdata(pdev),
			gate_free_user);
		msleep(500);
	}
	mutex_unlock(&icap->icap_lock);
}

static int set_freqs(struct icap* icap, unsigned short* freqs, int num_freqs)
{
	int i;
	int err;
	u32 val;

	for(i = 0; i < min(ICAP_MAX_NUM_CLOCKS, num_freqs); ++i) {
		if (freqs[i] == 0)
			continue;

		val = reg_rd(icap->icap_clock_bases[i] +
			OCL_CLKWIZ_STATUS_OFFSET);
		if ((val & 0x1) == 0) {
			ICAP_ERR(icap, "clockwiz %d is busy", i);
			err = -EBUSY;
			goto done;
		}
	}

	memcpy(icap->icap_ocl_frequency, freqs,
		sizeof(*freqs) * min(ICAP_MAX_NUM_CLOCKS, num_freqs));

	icap_freeze_axi_gate(icap, GATE_FREEZE_USER);
	err = icap_ocl_freqscaling(icap, false);
	icap_free_axi_gate(icap, gate_free_user);

done:
	return err;

}

static int set_and_verify_freqs(struct icap* icap, unsigned short* freqs, int num_freqs)
{
	int i;
	int err;
	u32 clock_freq_counter, request_in_khz, tolerance;

	err = set_freqs(icap, freqs, num_freqs);
	if(err)
		return err;

	for(i = 0; i <min(ICAP_MAX_NUM_CLOCKS, num_freqs); ++i) {
		if(!freqs[i])
			continue;
		clock_freq_counter = icap_get_clock_frequency_counter_khz(icap, i);
		if(clock_freq_counter == 0){
			err = -EDOM;
			break;
		}
		request_in_khz =freqs[i]*1000;
		tolerance = freqs[i]*50;
		if(tolerance < abs(clock_freq_counter-request_in_khz)){
			ICAP_ERR(icap, "Frequency is higher than tolerance value, request %u"
					"khz, actual %u khz", request_in_khz, clock_freq_counter);
			err = -EDOM;
			break;
		}
	}

	return err;
}

static int icap_ocl_set_freqscaling(struct platform_device *pdev,
	unsigned int region, unsigned short *freqs, int num_freqs)
{
	struct icap *icap = platform_get_drvdata(pdev);
	int err = 0;

	/* Can only be done from mgmt pf. */
	if (!ICAP_PRIVILEGED(icap))
		return -EPERM;

	/* For now, only PR region 0 is supported. */
	if (region != 0)
		return -EINVAL;

	mutex_lock(&icap->icap_lock);

	err = set_freqs(icap, freqs, num_freqs);

	mutex_unlock(&icap->icap_lock);

	return err;
}

static int icap_ocl_update_clock_freq_topology(struct platform_device *pdev, struct xclmgmt_ioc_freqscaling* freq_obj)
{
	struct icap *icap = platform_get_drvdata(pdev);
	struct clock_freq_topology *topology = 0;
	int num_clocks = 0;
	int i = 0;
	int err = 0;

	mutex_lock(&icap->icap_lock);
	if(icap->icap_clock_freq_topology) {
	        topology = (struct clock_freq_topology*)icap->icap_clock_freq_topology;
		num_clocks = topology->m_count;
		ICAP_INFO(icap, "Num clocks is %d", num_clocks);
		for(i = 0; i < ARRAY_SIZE(freq_obj->ocl_target_freq); i++) {
			ICAP_INFO(icap, "requested frequency is : "
				"%d xclbin freq is: %d",
				freq_obj->ocl_target_freq[i],
				topology-> m_clock_freq[i].m_freq_Mhz);
			if(freq_obj->ocl_target_freq[i] >
				topology-> m_clock_freq[i].m_freq_Mhz) {
				ICAP_ERR(icap, "Unable to set frequency as "
					"requested frequency %d is greater "
					"than set by xclbin %d",
					freq_obj->ocl_target_freq[i],
					topology-> m_clock_freq[i].m_freq_Mhz);
				err = -EDOM;
				goto done;
			}
		}
	}
	else{
		ICAP_ERR(icap, "ERROR: There isn't a hardware accelerator loaded in the dynamic region."
			" Validation of accelerator frequencies cannot be determine");
		err = -EDOM;
		goto done;
	}

	err = set_and_verify_freqs(icap, freq_obj->ocl_target_freq, ARRAY_SIZE(freq_obj->ocl_target_freq));

done:
	mutex_unlock(&icap->icap_lock);
	return err;
}

static int icap_ocl_get_freqscaling(struct platform_device *pdev,
	unsigned int region, unsigned short *freqs, int num_freqs)
{
	int i;
	struct icap *icap = platform_get_drvdata(pdev);

	/* For now, only PR region 0 is supported. */
	if (region != 0)
		return -EINVAL;

	mutex_lock(&icap->icap_lock);
	for (i = 0; i < min(ICAP_MAX_NUM_CLOCKS, num_freqs); i++)
		freqs[i] = icap_get_ocl_frequency(icap, i);
	mutex_unlock(&icap->icap_lock);

	return 0;
}

static inline bool mig_calibration_done(struct icap *icap)
{
	return (reg_rd(&icap->icap_state->igs_state) & BIT(0)) != 0;
}

/* Check for MIG calibration. */
static int calibrate_mig(struct icap *icap)
{
	int i;

	for(i = 0; i < 10 && !mig_calibration_done(icap); ++i)
		msleep(500);

	if (!mig_calibration_done(icap)) {
		ICAP_ERR(icap,
			"MIG calibration timeout after bitstream download");
		return -ETIMEDOUT;
	}

	return 0;
}

static inline void free_clock_freq_topology(struct icap *icap)
{
	vfree(icap->icap_clock_freq_topology);
	icap->icap_clock_freq_topology = NULL;
	icap->icap_clock_freq_topology_length = 0;
}

static int icap_setup_clock_freq_topology(struct icap *icap,
	const char __user *buffer, unsigned long length)
{
	int err;

	if (length == 0)
		return 0;

	free_clock_freq_topology(icap);

	icap->icap_clock_freq_topology = vmalloc(length);
	if (!icap->icap_clock_freq_topology)
		return -ENOMEM;

	err = copy_from_user(icap->icap_clock_freq_topology, buffer, length);
	if (err) {
		free_clock_freq_topology(icap);
		return -EFAULT;
	}
	icap->icap_clock_freq_topology_length = length;

	return 0;
}

static inline void free_clear_bitstream(struct icap *icap)
{
	vfree(icap->icap_clear_bitstream);
	icap->icap_clear_bitstream = NULL;
	icap->icap_clear_bitstream_length = 0;
}

static int icap_setup_clear_bitstream(struct icap *icap,
	const char __user *buffer, unsigned long length)
{
	int err;

	if (length == 0)
		return 0;

	free_clear_bitstream(icap);

	icap->icap_clear_bitstream = vmalloc(length);
	if (!icap->icap_clear_bitstream)
		return -ENOMEM;

	err = copy_from_user(icap->icap_clear_bitstream, buffer, length);
	if (err) {
		free_clear_bitstream(icap);
		return -EFAULT;
	}
	icap->icap_clear_bitstream_length = length;

	return 0;
}

static int wait_for_done(struct icap *icap)
{
	u32 w;
	int i = 0;

	for (i = 0; i < 10; i++) {
		udelay(5);
		w = reg_rd(&icap->icap_regs->ir_sr);
		ICAP_INFO(icap, "XHWICAP_SR: %x", w);
		if (w & 0x5)
			return 0;
	}

	ICAP_ERR(icap, "bitstream download timeout");
	return -ETIMEDOUT;
}

static int icap_write(struct icap *icap, const u32 *word_buf, int size)
{
	int i;
	u32 value = 0;

	for (i = 0; i < size; i++) {
		value = be32_to_cpu(word_buf[i]);
		reg_wr(&icap->icap_regs->ir_wf, value);
	}

	reg_wr(&icap->icap_regs->ir_cr, 0x1);

	for (i = 0; i < 20; i++) {
		value = reg_rd(&icap->icap_regs->ir_cr);
		if ((value & 0x1) == 0)
			return 0;
		ndelay(50);
	}

	ICAP_ERR(icap, "writing %d dwords timeout", size);
	return -EIO;
}

static uint64_t icap_get_section_size(struct icap *icap, enum axlf_section_kind kind)
{
	uint64_t size = 0;

	switch(kind){
		case IP_LAYOUT:
			size = sizeof_sect(icap->ip_layout, m_ip_data);
			break;
		case MEM_TOPOLOGY:
			size = sizeof_sect(icap->mem_topo, m_mem_data);
			break;
		case DEBUG_IP_LAYOUT:
			size = sizeof_sect(icap->debug_layout, m_debug_ip_data);
			break;
		case CONNECTIVITY:
			size = sizeof_sect(icap->connectivity, m_connection);
			break;
		default:
			break;
	}

	return size;
}

static int bitstream_parse_header(struct icap *icap, const unsigned char *Data,
	unsigned int Size, XHwIcap_Bit_Header *Header)
{
	unsigned int I;
	unsigned int Len;
	unsigned int Tmp;
	unsigned int Index;

	/* Start Index at start of bitstream */
	Index = 0;

	/* Initialize HeaderLength.  If header returned early inidicates
	 * failure.
	 */
	Header->HeaderLength = XHI_BIT_HEADER_FAILURE;

	/* Get "Magic" length */
	Header->MagicLength = Data[Index++];
	Header->MagicLength = (Header->MagicLength << 8) | Data[Index++];

	/* Read in "magic" */
	for (I = 0; I < Header->MagicLength - 1; I++) {
		Tmp = Data[Index++];
		if (I%2 == 0 && Tmp != XHI_EVEN_MAGIC_BYTE)
			return -1;   /* INVALID_FILE_HEADER_ERROR */

		if (I%2 == 1 && Tmp != XHI_ODD_MAGIC_BYTE)
			return -1;   /* INVALID_FILE_HEADER_ERROR */

	}

	/* Read null end of magic data. */
	Tmp = Data[Index++];

	/* Read 0x01 (short) */
	Tmp = Data[Index++];
	Tmp = (Tmp << 8) | Data[Index++];

	/* Check the "0x01" half word */
	if (Tmp != 0x01)
		return -1;	 /* INVALID_FILE_HEADER_ERROR */

	/* Read 'a' */
	Tmp = Data[Index++];
	if (Tmp != 'a')
		return -1;	  /* INVALID_FILE_HEADER_ERROR	*/

	/* Get Design Name length */
	Len = Data[Index++];
	Len = (Len << 8) | Data[Index++];

	/* allocate space for design name and final null character. */
	Header->DesignName = kmalloc(Len, GFP_KERNEL);

	/* Read in Design Name */
	for (I = 0; I < Len; I++)
		Header->DesignName[I] = Data[Index++];


	if (Header->DesignName[Len-1] != '\0')
		return -1;

	/* Read 'b' */
	Tmp = Data[Index++];
	if (Tmp != 'b')
		return -1;	/* INVALID_FILE_HEADER_ERROR */

	/* Get Part Name length */
	Len = Data[Index++];
	Len = (Len << 8) | Data[Index++];

	/* allocate space for part name and final null character. */
	Header->PartName = kmalloc(Len, GFP_KERNEL);

	/* Read in part name */
	for (I = 0; I < Len; I++)
		Header->PartName[I] = Data[Index++];

	if (Header->PartName[Len-1] != '\0')
		return -1;

	/* Read 'c' */
	Tmp = Data[Index++];
	if (Tmp != 'c')
		return -1;	/* INVALID_FILE_HEADER_ERROR */

	/* Get date length */
	Len = Data[Index++];
	Len = (Len << 8) | Data[Index++];

	/* allocate space for date and final null character. */
	Header->Date = kmalloc(Len, GFP_KERNEL);

	/* Read in date name */
	for (I = 0; I < Len; I++)
		Header->Date[I] = Data[Index++];

	if (Header->Date[Len - 1] != '\0')
		return -1;

	/* Read 'd' */
	Tmp = Data[Index++];
	if (Tmp != 'd')
		return -1;	/* INVALID_FILE_HEADER_ERROR  */

	/* Get time length */
	Len = Data[Index++];
	Len = (Len << 8) | Data[Index++];

	/* allocate space for time and final null character. */
	Header->Time = kmalloc(Len, GFP_KERNEL);

	/* Read in time name */
	for (I = 0; I < Len; I++)
		Header->Time[I] = Data[Index++];

	if (Header->Time[Len - 1] != '\0')
		return -1;

	/* Read 'e' */
	Tmp = Data[Index++];
	if (Tmp != 'e')
		return -1;	/* INVALID_FILE_HEADER_ERROR */

	/* Get byte length of bitstream */
	Header->BitstreamLength = Data[Index++];
	Header->BitstreamLength = (Header->BitstreamLength << 8) | Data[Index++];
	Header->BitstreamLength = (Header->BitstreamLength << 8) | Data[Index++];
	Header->BitstreamLength = (Header->BitstreamLength << 8) | Data[Index++];
	Header->HeaderLength = Index;

	ICAP_INFO(icap, "Design \"%s\"", Header->DesignName);
	ICAP_INFO(icap, "Part \"%s\"", Header->PartName);
	ICAP_INFO(icap, "Timestamp \"%s %s\"", Header->Time, Header->Date);
	ICAP_INFO(icap, "Raw data size 0x%x", Header->BitstreamLength);
	return 0;
}

static int bitstream_helper(struct icap *icap, const u32 *word_buffer,
	unsigned word_count)
{
	unsigned remain_word;
	unsigned word_written = 0;
	int wr_fifo_vacancy = 0;
	int err = 0;

	for (remain_word = word_count; remain_word > 0;
		remain_word -= word_written, word_buffer += word_written) {
		wr_fifo_vacancy = reg_rd(&icap->icap_regs->ir_wfv);
		if (wr_fifo_vacancy <= 0) {
			ICAP_ERR(icap, "no vacancy: %d", wr_fifo_vacancy);
			err = -EIO;
			break;
		}
		word_written = (wr_fifo_vacancy < remain_word) ?
			wr_fifo_vacancy : remain_word;
		if (icap_write(icap, word_buffer, word_written) != 0) {
			err = -EIO;
			break;
		}
	}

	return err;
}

static long icap_download(struct icap *icap, const char *buffer,
	unsigned long length)
{
	long err = 0;
	XHwIcap_Bit_Header bit_header = { 0 };
	unsigned numCharsRead = DMA_HWICAP_BITFILE_BUFFER_SIZE;
	unsigned byte_read;

	BUG_ON(!buffer);
	BUG_ON(!length);

	if (bitstream_parse_header(icap, buffer,
		DMA_HWICAP_BITFILE_BUFFER_SIZE, &bit_header)) {
		err = -EINVAL;
		goto free_buffers;
	}

	if ((bit_header.HeaderLength + bit_header.BitstreamLength) > length) {
		err = -EINVAL;
		goto free_buffers;
	}

	buffer += bit_header.HeaderLength;

	for (byte_read = 0; byte_read < bit_header.BitstreamLength;
		byte_read += numCharsRead) {
		numCharsRead = bit_header.BitstreamLength - byte_read;
		if (numCharsRead > DMA_HWICAP_BITFILE_BUFFER_SIZE)
			numCharsRead = DMA_HWICAP_BITFILE_BUFFER_SIZE;

		err = bitstream_helper(icap, (u32 *)buffer,
			numCharsRead / sizeof (u32));
		if (err)
			goto free_buffers;
		buffer += numCharsRead;
	}

	err = wait_for_done(icap);

free_buffers:
	kfree(bit_header.DesignName);
	kfree(bit_header.PartName);
	kfree(bit_header.Date);
	kfree(bit_header.Time);
	return err;
}

static const struct axlf_section_header* get_axlf_section_hdr(
	struct icap *icap, const struct axlf* top, enum axlf_section_kind kind)
{
	int i;
	const struct axlf_section_header *hdr = NULL;

	ICAP_INFO(icap,
		"trying to find section header for axlf section %d", kind);

	for(i = 0; i < top->m_header.m_numSections; i++)
	{
		ICAP_INFO(icap, "saw section header: %d",
			top->m_sections[i].m_sectionKind);
		if(top->m_sections[i].m_sectionKind == kind) {
			hdr = &top->m_sections[i];
			break;
		}
	}

	if (hdr) {
		if((hdr->m_sectionOffset + hdr->m_sectionSize) >
			top->m_header.m_length) {
			ICAP_INFO(icap, "found section is invalid");
			hdr = NULL;
		} else {
			ICAP_INFO(icap, "header offset: %llu, size: %llu",
				hdr->m_sectionOffset, hdr->m_sectionSize);
		}
	} else {
		ICAP_INFO(icap, "could not find section header %d", kind);
	}

	return hdr;
}

static int alloc_and_get_axlf_section(struct icap *icap,
	const struct axlf* top, enum axlf_section_kind kind, char __user *buf,
	void **addr, uint64_t *size)
{
	void *section = NULL;
	const struct axlf_section_header* hdr =
		get_axlf_section_hdr(icap, top, kind);

	if (hdr == NULL)
		return -EINVAL;

	section = vmalloc(hdr->m_sectionSize);
	if(section == NULL)
		return -ENOMEM;

	if (copy_from_user(section, buf + hdr->m_sectionOffset,
		hdr->m_sectionSize) != 0) {
		vfree(section);
		return -EFAULT;
	}

	*addr = section;
	*size = hdr->m_sectionSize;
	return 0;
}

static int icap_download_boot_firmware(struct platform_device *pdev)
{
	struct icap *icap = platform_get_drvdata(pdev);
	struct pci_dev *pcidev = XOCL_PL_TO_PCI_DEV(pdev);
	struct pci_dev *pcidev_user = NULL;
	xdev_handle_t xdev = xocl_get_xdev(pdev);
	int funcid = PCI_FUNC(pcidev->devfn);
	int slotid = PCI_SLOT(pcidev->devfn);
	unsigned short deviceid = pcidev->device;
	struct axlf *bin_obj_axlf;
	const struct firmware *fw;
	char fw_name[128];
	XHwIcap_Bit_Header bit_header = { 0 };
	long err = 0;
	uint64_t length = 0;
	uint64_t primaryFirmwareOffset = 0;
	uint64_t primaryFirmwareLength = 0;
	uint64_t secondaryFirmwareOffset = 0;
	uint64_t secondaryFirmwareLength = 0;
	uint64_t mbBinaryOffset = 0;
	uint64_t mbBinaryLength = 0;
	const struct axlf_section_header* primaryHeader = 0;
	const struct axlf_section_header* secondaryHeader = 0;
	const struct axlf_section_header* mbHeader = 0;
	bool load_mbs = false;

	/* Can only be done from mgmt pf. */
	if (!ICAP_PRIVILEGED(icap))
		return -EPERM;

	/* Read dsabin from file system. */

	if (funcid != 0) {
		pcidev_user = pci_get_slot(pcidev->bus,
			PCI_DEVFN(slotid, funcid - 1));
		if (!pcidev_user) {
			pcidev_user = pci_get_device(pcidev->vendor,
				pcidev->device + 1, NULL);
		}
		if (pcidev_user)
			deviceid = pcidev_user->device;
	}

	snprintf(fw_name, sizeof(fw_name),
		"xilinx/%04x-%04x-%04x-%016llx.dsabin",
		le16_to_cpu(pcidev->vendor),
		le16_to_cpu(deviceid),
		le16_to_cpu(pcidev->subsystem_device),
		le64_to_cpu(xocl_get_timestamp(xdev)));
	ICAP_INFO(icap, "try load dsabin %s", fw_name);
	err = request_firmware(&fw, fw_name, &pcidev->dev);
	if (err) {
		snprintf(fw_name, sizeof(fw_name),
			"xilinx/%04x-%04x-%04x-%016llx.dsabin",
			le16_to_cpu(pcidev->vendor),
			le16_to_cpu(deviceid + 1),
			le16_to_cpu(pcidev->subsystem_device),
			le64_to_cpu(xocl_get_timestamp(xdev)));
		ICAP_INFO(icap, "try load dsabin %s", fw_name);
		err = request_firmware(&fw, fw_name, &pcidev->dev);
	}
	/* Retry with the legacy dsabin. */
	if(err) {
		snprintf(fw_name, sizeof(fw_name),
			"xilinx/%04x-%04x-%04x-%016llx.dsabin",
			le16_to_cpu(pcidev->vendor),
			le16_to_cpu(pcidev->device + 1),
			le16_to_cpu(pcidev->subsystem_device),
			le64_to_cpu(0x0000000000000000));
		ICAP_INFO(icap, "try load dsabin %s", fw_name);
		err = request_firmware(&fw, fw_name, &pcidev->dev);
	}
	if (err) {
		/* Give up on finding .dsabin. */
		ICAP_ERR(icap, "unable to find firmware, giving up");
		return err;
	}

	/* Grab lock and touch hardware. */
	mutex_lock(&icap->icap_lock);

	if(xocl_mb_sched_on(xdev)) {
		/* Try locating the microblaze binary. */
		bin_obj_axlf = (struct axlf*)fw->data;
		mbHeader = get_axlf_section_hdr(icap, bin_obj_axlf, SCHED_FIRMWARE);
		if(mbHeader) {
			mbBinaryOffset = mbHeader->m_sectionOffset;
			mbBinaryLength = mbHeader->m_sectionSize;
			length = bin_obj_axlf->m_header.m_length;
			xocl_mb_load_sche_image(xdev, fw->data + mbBinaryOffset,
				mbBinaryLength);
			ICAP_INFO(icap, "stashed mb sche binary");
			load_mbs = true;
		}
	}

	if(xocl_mb_mgmt_on(xdev)) {
		/* Try locating the board mgmt binary. */
		bin_obj_axlf = (struct axlf*)fw->data;
		mbHeader = get_axlf_section_hdr(icap, bin_obj_axlf, FIRMWARE);
		if(mbHeader) {
			mbBinaryOffset = mbHeader->m_sectionOffset;
			mbBinaryLength = mbHeader->m_sectionSize;
			length = bin_obj_axlf->m_header.m_length;
			xocl_mb_load_mgmt_image(xdev, fw->data + mbBinaryOffset,
				mbBinaryLength);
			ICAP_INFO(icap, "stashed mb mgmt binary");
			load_mbs = true;
		}
	}

	if(load_mbs)
		xocl_mb_reset(xdev);


	if (memcmp(fw->data, ICAP_XCLBIN_V2, sizeof (ICAP_XCLBIN_V2)) != 0) {
		ICAP_ERR(icap, "invalid firmware %s", fw_name);
		err = -EINVAL;
		goto done;
	}

	ICAP_INFO(icap, "boot_firmware in axlf format");
	bin_obj_axlf = (struct axlf*)fw->data;
	length = bin_obj_axlf->m_header.m_length;
	/* Match the xclbin with the hardware. */
	if(!xocl_verify_timestamp(xdev,
		bin_obj_axlf->m_header.m_featureRomTimeStamp)) {
		ICAP_ERR(icap, "timestamp of ROM did not match xclbin");
		err = -EINVAL;
		goto done;
	}
	ICAP_INFO(icap, "VBNV and timestamps matched");

	if (xocl_xrt_version_check(xdev, bin_obj_axlf, true)) {
		ICAP_ERR(icap, "Major version does not match xrt");
		err = -EINVAL;
		goto done;
	}
	ICAP_INFO(icap, "runtime version matched");

	primaryHeader = get_axlf_section_hdr(icap, bin_obj_axlf, BITSTREAM);
	secondaryHeader = get_axlf_section_hdr(icap, bin_obj_axlf,
		CLEARING_BITSTREAM);
	if(primaryHeader) {
		primaryFirmwareOffset = primaryHeader->m_sectionOffset;
		primaryFirmwareLength = primaryHeader->m_sectionSize;
	}
	if(secondaryHeader) {
		secondaryFirmwareOffset = secondaryHeader->m_sectionOffset;
		secondaryFirmwareLength = secondaryHeader->m_sectionSize;
	}

	if (length > fw->size) {
		err = -EINVAL;
		goto done;
	}

	if ((primaryFirmwareOffset + primaryFirmwareLength) > length) {
		err = -EINVAL;
		goto done;
	}

	if ((secondaryFirmwareOffset + secondaryFirmwareLength) > length) {
		err = -EINVAL;
		goto done;
	}

	if (primaryFirmwareLength) {
		ICAP_INFO(icap,
			"found second stage bitstream of size 0x%llx in %s",
			primaryFirmwareLength, fw_name);
		err = icap_download(icap, fw->data + primaryFirmwareOffset,
			primaryFirmwareLength);
		/*
		 * If we loaded a new second stage, we do not need the
		 * previously stashed clearing bitstream if any.
		 */
		free_clear_bitstream(icap);
		if (err) {
			ICAP_ERR(icap,
				"failed to download second stage bitstream");
			goto done;
		}
		ICAP_INFO(icap, "downloaded second stage bitstream");
	}

	/*
	 * If both primary and secondary bitstreams have been provided then
	 * ignore the previously stashed bitstream if any. If only secondary
	 * bitstream was provided, but we found a previously stashed bitstream
	 * we should use the latter since it is more appropriate for the
	 * current state of the device
	 */
	if (secondaryFirmwareLength && (primaryFirmwareLength ||
		!icap->icap_clear_bitstream)) {
		free_clear_bitstream(icap);
		icap->icap_clear_bitstream = vmalloc(secondaryFirmwareLength);
		if (!icap->icap_clear_bitstream) {
			err = -ENOMEM;
			goto done;
		}
		icap->icap_clear_bitstream_length = secondaryFirmwareLength;
		memcpy(icap->icap_clear_bitstream,
			fw->data + secondaryFirmwareOffset,
			icap->icap_clear_bitstream_length);
		ICAP_INFO(icap, "found clearing bitstream of size 0x%lx in %s",
			icap->icap_clear_bitstream_length, fw_name);
	} else if (icap->icap_clear_bitstream) {
		ICAP_INFO(icap,
			"using existing clearing bitstream of size 0x%lx",
		       icap->icap_clear_bitstream_length);
	}

	if (icap->icap_clear_bitstream &&
		bitstream_parse_header(icap, icap->icap_clear_bitstream,
		DMA_HWICAP_BITFILE_BUFFER_SIZE, &bit_header)) {
		err = -EINVAL;
		free_clear_bitstream(icap);
	}

done:
	mutex_unlock(&icap->icap_lock);
	release_firmware(fw);
	kfree(bit_header.DesignName);
	kfree(bit_header.PartName);
	kfree(bit_header.Date);
	kfree(bit_header.Time);
	ICAP_INFO(icap, "%s err: %ld", __FUNCTION__, err);
	return err;
}


static long icap_download_clear_bitstream(struct icap *icap)
{
	long err = 0;
	const char *buffer = icap->icap_clear_bitstream;
	unsigned long length = icap->icap_clear_bitstream_length;

	ICAP_INFO(icap, "downloading clear bitstream of length 0x%lx", length);

	if (!buffer)
		return 0;

	err = icap_download(icap, buffer, length);

	free_clear_bitstream(icap);
	return err;
}

/*
 * This function should be called with icap_mutex lock held
 */
static long axlf_set_freqscaling(struct icap *icap, struct platform_device *pdev,
	const char __user *clk_buf, unsigned long length)
{
	long err = 0;
	char *buffer = NULL;
	struct clock_freq_topology *freqs = NULL;
	int clock_type_count = 0;
	int i = 0;
	struct clock_freq *freq = NULL;
	int data_clk_count = 0;
	int kernel_clk_count = 0;
	int system_clk_count = 0;
	unsigned short target_freqs[4] = {0};

	buffer = kmalloc(length, GFP_KERNEL);
	if (!buffer) {
		ICAP_ERR(icap, "Unable to allocate memory for memory topology");
		err = -ENOMEM;
		goto free_buffers;
	}

	if (copy_from_user(buffer, clk_buf, length)) {
		ICAP_ERR(icap, "Unable to copy from userspace for memory topology");
		err = -EFAULT;
		goto free_buffers;
	}

	freqs = (struct clock_freq_topology*)buffer;
	if(freqs->m_count > 4) {
		err = -EDOM;
		ICAP_ERR(icap, "More than 4 clocks found in clock topology");
		goto free_buffers;
	}

	//Error checks - we support 1 data clk (reqd), one kernel clock(reqd) and
	//at most 2 system clocks (optional/reqd for aws).
	//Data clk needs to be the first entry, followed by kernel clock
	//and then system clocks
	//

	for (i = 0; i < freqs->m_count; i++)
	{
		freq = &(freqs->m_clock_freq[i]);
		if(freq->m_type == CT_DATA) {
			data_clk_count++;
		}
		if(freq->m_type == CT_KERNEL) {
			kernel_clk_count++;
		}
		if(freq->m_type == CT_SYSTEM) {
			system_clk_count++;
		}
	}

	if(data_clk_count !=1) {
		err = -EDOM;
		ICAP_ERR(icap, "Data clock not found in clock topology");
		goto free_buffers;
	}
	if(kernel_clk_count !=1) {
		err = -EDOM;
		ICAP_ERR(icap, "Kernel clock not found in clock topology");
		goto free_buffers;
	}
	if(system_clk_count > 2) {
		err = -EDOM;
		ICAP_ERR(icap,
			"More than 2 system clocks found in clock topology");
		goto free_buffers;
	}

	for (i = 0; i < freqs->m_count; i++) {
		freq = &(freqs->m_clock_freq[i]);
		if(freq->m_type == CT_DATA) {
			target_freqs[0] = freq->m_freq_Mhz;
		}
	}

	for (i = 0; i < freqs->m_count; i++) {
		freq = &(freqs->m_clock_freq[i]);
		if(freq->m_type == CT_KERNEL) {
			target_freqs[1] = freq->m_freq_Mhz;
		}
	}

	clock_type_count = 2;
	for (i = 0; i < freqs->m_count; i++) {
		freq = &(freqs->m_clock_freq[i]);
		if(freq->m_type == CT_SYSTEM) {
			target_freqs[clock_type_count++] = freq->m_freq_Mhz;
		}
	}


	ICAP_INFO(icap, "setting clock freq, "
		"num: %lu, data_freq: %d , clk_freq: %d, "
		"sys_freq[0]: %d, sys_freq[1]: %d",
		ARRAY_SIZE(target_freqs), target_freqs[0], target_freqs[1],
		target_freqs[2], target_freqs[3]);
	err = set_freqs(icap, target_freqs, 4);

free_buffers:
	kfree(buffer);
	return err;
}

static int icap_download_user(struct icap *icap, const char __user *bit_buf,
	unsigned long length)
{
	long err = 0;
	XHwIcap_Bit_Header bit_header = { 0 };
	char *buffer = NULL;
	unsigned numCharsRead = DMA_HWICAP_BITFILE_BUFFER_SIZE;
	unsigned byte_read;

	ICAP_INFO(icap, "downloading bitstream, length: %lu", length);

	icap_freeze_axi_gate(icap, GATE_FREEZE_USER);

	err = icap_download_clear_bitstream(icap);
	if (err)
		goto free_buffers;

	buffer = kmalloc(DMA_HWICAP_BITFILE_BUFFER_SIZE, GFP_KERNEL);
	if (!buffer) {
		err = -ENOMEM;
		goto free_buffers;
	}

	if (copy_from_user(buffer, bit_buf, DMA_HWICAP_BITFILE_BUFFER_SIZE)) {
		err = -EFAULT;
		goto free_buffers;
	}

	if (bitstream_parse_header(icap, buffer,
		DMA_HWICAP_BITFILE_BUFFER_SIZE, &bit_header)) {
		err = -EINVAL;
		goto free_buffers;
	}
	if ((bit_header.HeaderLength + bit_header.BitstreamLength) > length) {
		err = -EINVAL;
		goto free_buffers;
	}

	bit_buf += bit_header.HeaderLength;
	for (byte_read = 0; byte_read < bit_header.BitstreamLength;
		byte_read += numCharsRead) {
		numCharsRead = bit_header.BitstreamLength - byte_read;
		if (numCharsRead > DMA_HWICAP_BITFILE_BUFFER_SIZE)
			numCharsRead = DMA_HWICAP_BITFILE_BUFFER_SIZE;
		if (copy_from_user(buffer, bit_buf, numCharsRead)) {
			err = -EFAULT;
			goto free_buffers;
		}

		bit_buf += numCharsRead;
		err = bitstream_helper(icap, (u32 *)buffer,
			numCharsRead / sizeof (u32));
		if (err)
			goto free_buffers;
	}

	err = wait_for_done(icap);
	if (err)
		goto free_buffers;

	/*
	 * Perform frequency scaling since PR download can silenty overwrite
	 * MMCM settings in static region changing the clock frequencies
	 * although ClockWiz CONFIG registers will misleading report the older
	 * configuration from before bitstream download as if nothing has
	 * changed.
	 */
	if (!err)
		err = icap_ocl_freqscaling(icap, true);

free_buffers:
	icap_free_axi_gate(icap, gate_free_user);
	kfree(buffer);
	kfree(bit_header.DesignName);
	kfree(bit_header.PartName);
	kfree(bit_header.Date);
	kfree(bit_header.Time);
	return err;
}

static int icap_download_bitstream_axlf(struct platform_device *pdev,
	const void __user *u_xclbin)
{
	struct icap *icap = platform_get_drvdata(pdev);
	struct axlf bin_obj;
	char __user *buffer = (char __user *)u_xclbin;
	long err = 0;
	uint64_t primaryFirmwareOffset = 0;
	uint64_t primaryFirmwareLength = 0;
	uint64_t secondaryFirmwareOffset = 0;
	uint64_t secondaryFirmwareLength = 0;
	uint64_t section_size = 0;
	const struct axlf_section_header* primaryHeader = NULL;
	const struct axlf_section_header* clockHeader = NULL;
	const struct axlf_section_header* secondaryHeader = NULL;
	uint64_t copy_buffer_size = 0;
	struct axlf* copy_buffer = NULL;
	xdev_handle_t xdev = xocl_get_xdev(pdev);
	bool need_download;
	struct ip_layout* layout = NULL;
	struct mem_topology* memtopo = NULL;
	bool dna_check = false;
	int pid = pid_nr(task_tgid(current));
	int i;

	/* Can only be done from mgmt pf. */
	if (!ICAP_PRIVILEGED(icap))
		return -EPERM;

	if (copy_from_user((void *)&bin_obj, u_xclbin, sizeof(struct axlf)))
		return -EFAULT;
	if (memcmp(bin_obj.m_magic, ICAP_XCLBIN_V2, sizeof(ICAP_XCLBIN_V2)))
		return -EINVAL;

	err = !access_ok(VERIFY_READ, buffer, bin_obj.m_header.m_length);
	if (err) {
		return -EFAULT;
	}
	/*
	 * Copy headers in xclbin. Done before potentially skipping redownload
	 * due to freq scaling requirements.
	 */
	copy_buffer_size = bin_obj.m_header.m_numSections *
		sizeof(struct axlf_section_header) + sizeof(struct axlf);
	ICAP_INFO(icap, "copy-in headers, num sections: %d, size: %llu",
		bin_obj.m_header.m_numSections, copy_buffer_size);
	copy_buffer = (struct axlf *)vmalloc(copy_buffer_size);
	if(!copy_buffer) {
		ICAP_ERR(icap, "unable to alloc copy buffer for headers");
		return -ENOMEM;
	}
	if (copy_from_user((void *)copy_buffer, u_xclbin, copy_buffer_size)) {
		err = -EFAULT;
		goto dna_cert_fail;
	}

	if (xocl_xrt_version_check(xdev, &bin_obj, true)) {
		ICAP_ERR(icap, "XRT version does not match");
		err = -EINVAL;
		goto dna_cert_fail;
	}

	/* Match the xclbin with the hardware. */
	if (!xocl_verify_timestamp(xdev,
		bin_obj.m_header.m_featureRomTimeStamp)) {
		ICAP_ERR(icap, "timestamp of ROM did not match Xclbin\n");
		xocl_sysfs_error(xdev, "timestamp of ROM did not match Xclbin\n");
		err = -EINVAL;
		goto dna_cert_fail;
	}

	mutex_lock(&icap->icap_lock);

	ICAP_INFO(icap,
		"incoming xclbin ID: %016llx, on device xclbin ID:%016llx",
		bin_obj.m_uniqueId, icap->icap_bitstream_id);

	need_download = (icap->icap_bitstream_id != bin_obj.m_uniqueId);

	if(!need_download) {
		/*
		 * No need to download, if xclbin exists already.
		 * But, still need to reset CUs.
		 */
		if (!icap_bitstream_in_use(icap, pid)) {
			icap_freeze_axi_gate(icap, GATE_FREEZE_USER);
			msleep(50);
			icap_free_axi_gate(icap, gate_free_user);
			msleep(50);
		}
		ICAP_INFO(icap, "bitstream already exists, skip downloading");
	}

	mutex_unlock(&icap->icap_lock);

	if(!need_download)
		return 0;

	/*
	 * Find sections in xclbin.
	 */
	ICAP_INFO(icap, "finding CLOCK_FREQ_TOPOLOGY section");
	/* Read the CLOCK section but defer changing clocks to later */
	clockHeader = get_axlf_section_hdr(icap, copy_buffer, CLOCK_FREQ_TOPOLOGY);

	ICAP_INFO(icap, "finding ip layout section");
	err = alloc_and_get_axlf_section(icap, copy_buffer, IP_LAYOUT,
		buffer, (void **)&layout, &section_size);
	if (err != 0)
		goto dna_cert_fail;
	if (sizeof_sect(layout, m_ip_data) > section_size) {
		err = -EINVAL;
		goto dna_cert_fail;
	}
	ICAP_INFO(icap, "finding mem topology section");
	err = alloc_and_get_axlf_section(icap, copy_buffer, MEM_TOPOLOGY,
		buffer, (void **)&memtopo, &section_size);
	if (err != 0)
		goto dna_cert_fail;

	if (sizeof_sect(memtopo, m_mem_data) > section_size) {
		err = -EINVAL;
		goto dna_cert_fail;
	}

	ICAP_INFO(icap, "finding bitstream sections");
	primaryHeader = get_axlf_section_hdr(icap, copy_buffer, BITSTREAM);
	if (primaryHeader == NULL) {
		err = -EINVAL;
		goto dna_cert_fail;
	}
	primaryFirmwareOffset = primaryHeader->m_sectionOffset;
	primaryFirmwareLength = primaryHeader->m_sectionSize;

	secondaryHeader = get_axlf_section_hdr(icap, copy_buffer,
		CLEARING_BITSTREAM);
	if(secondaryHeader) {
		if (XOCL_PL_TO_PCI_DEV(pdev)->device == 0x7138) {
			err = -EINVAL;
			goto dna_cert_fail;
		} else {
			secondaryFirmwareOffset =
				secondaryHeader->m_sectionOffset;
			secondaryFirmwareLength =
				secondaryHeader->m_sectionSize;
		}
	}


	mutex_lock(&icap->icap_lock);

	if (icap_bitstream_in_use(icap, pid)) {
		ICAP_ERR(icap, "bitstream is locked, can't download new one");
		err = -EBUSY;
		goto unlock;
	}

	/* All clear, go ahead and start fiddling with hardware */

	if (clockHeader != NULL) {
		uint64_t clockFirmwareOffset = clockHeader->m_sectionOffset;
		uint64_t clockFirmwareLength = clockHeader->m_sectionSize;
		buffer = (char __user *)u_xclbin;
		buffer += clockFirmwareOffset;
		err = axlf_set_freqscaling(icap, pdev, buffer, clockFirmwareLength);
		if (err)
			goto unlock;
		err = icap_setup_clock_freq_topology(icap, buffer, clockFirmwareLength);
		if (err)
			goto unlock;
	}


	icap->icap_bitstream_id = 0;
	uuid_copy(&icap->icap_bitstream_uuid, &uuid_null);

	buffer = (char __user *)u_xclbin;
	buffer += primaryFirmwareOffset;
	err = icap_download_user(icap, buffer, primaryFirmwareLength);
	if (err)
		goto unlock;

	/* Destroy all dynamically add sub-devices*/
	xocl_subdev_destroy_by_id(xdev, XOCL_SUBDEV_DNA);
	xocl_subdev_destroy_by_id(xdev, XOCL_SUBDEV_MIG);

	/*
	 * Add sub device dynamically.
	 *
	 * restrict any dynamically added sub-device and 1 base address,
	 * Has pre-defined length
	 *  Ex:    "ip_data": {
	 *         "m_type": "IP_DNASC",
	 *         "properties": "0x0",
	 *         "m_base_address": "0x1100000", <--  base address
	 *         "m_name": "slr0\/dna_self_check_0"
	 */
	for(i = 0; i < layout->m_count; ++i) {
		struct xocl_subdev_info subdev_info = { 0 };
		struct resource res = { 0 };
		struct ip_data *ip = &layout->m_ip_data[i];

		if(ip->m_type == IP_KERNEL)
			continue;

		if(ip->m_type == IP_DDR4_CONTROLLER) {
			uint32_t memidx = ip->properties;

			if (!memtopo || ip->properties >= memtopo->m_count ||
				memtopo->m_mem_data[memidx].m_type !=
				MEM_DDR4) {
				ICAP_ERR(icap, "bad ECC controller index: %u",
					ip->properties);
				continue;
			}
			if (!memtopo->m_mem_data[memidx].m_used) {
				ICAP_INFO(icap,
					"ignore ECC controller for: %s",
					memtopo->m_mem_data[memidx].m_tag);
				continue;
			}
			err = xocl_subdev_get_devinfo(XOCL_SUBDEV_MIG,
				&subdev_info, &res);
			if (err) {
				ICAP_ERR(icap, "can't get MIG subdev info");
				goto done;
			}
			res.start += ip->m_base_address;
			res.end += ip->m_base_address;
			subdev_info.priv_data =
				memtopo->m_mem_data[memidx].m_tag;
			subdev_info.data_len =
				sizeof (memtopo->m_mem_data[memidx].m_tag);
			err = xocl_subdev_create_multi_inst(xdev, &subdev_info);
			if (err) {
				ICAP_ERR(icap, "can't create MIG subdev");
				goto done;
			}
		}
		if(ip->m_type == IP_DNASC){
			dna_check = true;
			err = xocl_subdev_get_devinfo(XOCL_SUBDEV_DNA,
				&subdev_info, &res);
			if (err) {
				ICAP_ERR(icap, "can't get DNA subdev info");
				goto done;
			}
			res.start += ip->m_base_address;
			res.end += ip->m_base_address;
			err = xocl_subdev_create_one(xdev, &subdev_info);
			if (err) {
				ICAP_ERR(icap, "can't create DNA subdev");
				goto done;
			}
		}
	}

	if (dna_check) {
		bool is_axi = ((xocl_dna_capability(xdev) & 0x1) != 0);

		/*
		 * Any error occurs here should return -EACCES for app to
		 * know that DNA has failed.
		 */
		err = -EACCES;

		ICAP_INFO(icap, "DNA version: %s", is_axi ? "AXI" : "BRAM");

		if(is_axi){
			uint32_t *cert = NULL;

			buffer = (char __user *)u_xclbin;
			if (alloc_and_get_axlf_section(icap, copy_buffer,
				DNA_CERTIFICATE, buffer,
				(void **)&cert, &section_size) != 0) {

				// We keep dna sub device if IP_DNASC presents
				ICAP_ERR(icap, "Can't get certificate section");
				goto dna_cert_fail;
			}

			ICAP_INFO(icap, "DNA Certificate Size 0x%llx", section_size);
			if(section_size % 64 || section_size < 576) {
				ICAP_ERR(icap, "Invalid certificate size");
			} else {
				xocl_dna_write_cert(xdev, cert, section_size);
			}

			vfree(cert);
		}

		/* Check DNA validation result. */
		if (0x1 & xocl_dna_status(xdev)) {
			err = 0; /* xclbin is valid */
		} else {
			ICAP_ERR(icap, "DNA inside xclbin is invalid");
			goto dna_cert_fail;
		}
	}

	buffer = (char __user *)u_xclbin;
	buffer += secondaryFirmwareOffset;
	err = icap_setup_clear_bitstream(icap, buffer, secondaryFirmwareLength);
	if (err)
		goto done;

	if ((xocl_is_unified(xdev) || XOCL_DSA_XPR_ON(xdev)))
		err = calibrate_mig(icap);
	if (err)
		goto done;

	/* Remember "this" bitstream, so avoid redownload the next time. */
	icap->icap_bitstream_id = bin_obj.m_uniqueId;
	if (!uuid_is_null(&bin_obj.m_header.uuid)) {
		uuid_copy(&icap->icap_bitstream_uuid, &bin_obj.m_header.uuid);
	} else {
		// Legacy xclbin, convert legacy id to new id
		memcpy(&icap->icap_bitstream_uuid,
			&bin_obj.m_header.m_timeStamp, 8);
	}

done:
	if (err) {
		xocl_subdev_destroy_by_id(xdev, XOCL_SUBDEV_DNA);
		xocl_subdev_destroy_by_id(xdev, XOCL_SUBDEV_MIG);
	}
unlock:
	mutex_unlock(&icap->icap_lock);
dna_cert_fail:
	ICAP_INFO(icap, "proc %d %s err: %ld", pid, __FUNCTION__, err);
	vfree(layout);
	vfree(memtopo);
	vfree(copy_buffer);
	return err;
}

/*
 * On x86_64, reset hwicap by loading special bitstream sequence which
 * forces the FPGA to reload from PROM.
 */
static int icap_reset_bitstream(struct platform_device *pdev)
{
/*
 * Booting FPGA from PROM
 * http://www.xilinx.com/support/documentation/user_guides/ug470_7Series_Config.pdf
 * Table 7.1
 */
#define DUMMY_WORD         0xFFFFFFFF
#define SYNC_WORD          0xAA995566
#define TYPE1_NOOP         0x20000000
#define TYPE1_WRITE_WBSTAR 0x30020001
#define WBSTAR_ADD10       0x00000000
#define WBSTAR_ADD11       0x01000000
#define TYPE1_WRITE_CMD    0x30008001
#define IPROG_CMD          0x0000000F
#define SWAP_ENDIAN_32(x)						\
	(unsigned)((((x) & 0xFF000000) >> 24) | (((x) & 0x00FF0000) >> 8) | \
		   (((x) & 0x0000FF00) << 8)  | (((x) & 0x000000FF) << 24))
	/*
	 * The bitstream is expected in big endian format
	 */
	const unsigned fpga_boot_seq[] = {				\
		SWAP_ENDIAN_32(DUMMY_WORD),				\
		SWAP_ENDIAN_32(SYNC_WORD),				\
		SWAP_ENDIAN_32(TYPE1_NOOP),				\
		SWAP_ENDIAN_32(TYPE1_WRITE_CMD),			\
		SWAP_ENDIAN_32(IPROG_CMD),				\
		SWAP_ENDIAN_32(TYPE1_NOOP),				\
		SWAP_ENDIAN_32(TYPE1_NOOP)				\
	};
	struct icap *icap = platform_get_drvdata(pdev);
	int i;

	/* Can only be done from mgmt pf. */
	if (!ICAP_PRIVILEGED(icap))
		return -EPERM;

	mutex_lock(&icap->icap_lock);

	if (icap_bitstream_in_use(icap, 0)) {
		mutex_unlock(&icap->icap_lock);
		ICAP_ERR(icap, "bitstream is locked, can't reset");
		return -EBUSY;
	}

	for (i = 0; i < ARRAY_SIZE(fpga_boot_seq); i++) {
		unsigned value = be32_to_cpu(fpga_boot_seq[i]);
		reg_wr(&icap->icap_regs->ir_wfv, value);
	}
	reg_wr(&icap->icap_regs->ir_cr, 0x1);

	msleep(4000);

	mutex_unlock(&icap->icap_lock);

	ICAP_INFO(icap, "reset bitstream is done");
	return 0;
}

static int icap_lock_unlock_peer_bitstream(struct icap *icap,
	const xuid_t *id, pid_t pid, bool lock)
{
	int err = 0;
	size_t resplen = sizeof (err);
	struct mailbox_req mbreq = { 0 };
	xdev_handle_t xdev = xocl_get_xdev(icap->icap_pdev);

	mbreq.req = lock ?
		MAILBOX_REQ_LOCK_BITSTREAM : MAILBOX_REQ_UNLOCK_BITSTREAM;
	uuid_copy(&mbreq.u.req_bit_lock.uuid, id);
	mbreq.u.req_bit_lock.pid = pid;
	/*
	 * We can't reach peer, if mailbox is not supported.
	 * In this case, we assume lock is done successfully.
	 */
	(void) xocl_peer_request(xdev, &mbreq, &err, &resplen,
		NULL, NULL);

	return err;
}

static int icap_lock_bitstream(struct platform_device *pdev, const xuid_t *id,
	pid_t pid)
{
	struct icap *icap = platform_get_drvdata(pdev);
	int err = 0;

	if (uuid_is_null(id)) {
		ICAP_ERR(icap, "proc %d invalid UUID", pid);
		return -EINVAL;
	}

	mutex_lock(&icap->icap_lock);

	if (ICAP_PRIVILEGED(icap)) {
		if (uuid_equal(id, &icap->icap_bitstream_uuid))
			err = add_user(icap, pid);
		else
			err = -EBUSY;

		if (err >= 0)
			err = icap->icap_bitstream_ref;
	}
	else
		err = icap_lock_unlock_peer_bitstream(icap, id, pid, true);

	ICAP_INFO(icap, "proc %d try to lock bitstream %pUb, ref=%d, err=%d",
		  pid, id, icap->icap_bitstream_ref, err);

	mutex_unlock(&icap->icap_lock);

	return err;
}

static int icap_unlock_bitstream(struct platform_device *pdev, const xuid_t *id,
	pid_t pid)
{
	struct icap *icap = platform_get_drvdata(pdev);
	int err = 0;

	if (id == NULL)
		id = &uuid_null;

	mutex_lock(&icap->icap_lock);

	if (ICAP_PRIVILEGED(icap)) {
		/* Force unlock. */
		if (uuid_is_null(id))
			del_all_users(icap);
		else if (uuid_equal(id, &icap->icap_bitstream_uuid))
			err = del_user(icap, pid);
		else
			err = -EINVAL;
		if (err >= 0)
			err = icap->icap_bitstream_ref;
	}
	else {
		err = icap_lock_unlock_peer_bitstream(icap, id, pid, false);
		if (err==0)
			xocl_exec_reset(xocl_get_xdev(pdev));
	}

	ICAP_INFO(icap, "proc %d try to unlock bitstream %pUb, ref=%d, err=%d",
		  pid, id, icap->icap_bitstream_ref, err);

	mutex_unlock(&icap->icap_lock);

	return err;
}


static int icap_parse_bitstream_axlf_section(struct platform_device *pdev,
	const void __user *u_xclbin, enum axlf_section_kind kind)
{
	struct icap *icap = platform_get_drvdata(pdev);
	struct axlf bin_obj;
	char __user *buffer = (char __user *)u_xclbin;
	long err = 0;
	uint64_t section_size = 0, sect_sz = 0;
	uint64_t copy_buffer_size = 0;
	struct axlf* copy_buffer = NULL;
	void **target = NULL;

	if (copy_from_user((void *)&bin_obj, u_xclbin, sizeof(struct axlf)))
		return -EFAULT;
	if (memcmp(bin_obj.m_magic, ICAP_XCLBIN_V2, sizeof(ICAP_XCLBIN_V2)))
		return -EINVAL;

	err = !access_ok(VERIFY_READ, buffer, bin_obj.m_header.m_length);
	if (err) {
		err = -EFAULT;
		goto done;
	}
	/*
	 * Copy headers in xclbin.
	 */
	copy_buffer_size = bin_obj.m_header.m_numSections *
		sizeof(struct axlf_section_header) + sizeof(struct axlf);
	ICAP_INFO(icap, "copy-in headers, num sections: %d, size: %llu",
		bin_obj.m_header.m_numSections, copy_buffer_size);
	copy_buffer = (struct axlf *)vmalloc(copy_buffer_size);
	if(!copy_buffer) {
		ICAP_ERR(icap, "unable to alloc copy buffer for headers");
		return -ENOMEM;
	}
	if (copy_from_user((void *)copy_buffer, u_xclbin, copy_buffer_size)) {
		err = -EFAULT;
		goto done;
	}

	mutex_lock(&icap->icap_lock);

	switch(kind){
		case IP_LAYOUT:
			target = (void **)&icap->ip_layout;
			break;
		case MEM_TOPOLOGY:
			target = (void **)&icap->mem_topo;
			break;
		case DEBUG_IP_LAYOUT:
			target = (void **)&icap->debug_layout;
			break;
		case CONNECTIVITY:
			target = (void **)&icap->connectivity;
			break;
		default:
			break;
	}
	if (target) {
		vfree(*target);
		*target = NULL;
	}
	err = alloc_and_get_axlf_section(icap, copy_buffer, kind,
		buffer, target, &section_size);
	if (err != 0)
		goto done;
	sect_sz = icap_get_section_size(icap, kind);
	if (sect_sz > section_size) {
		err = -EINVAL;
		goto done;
	}
done:
	if (err) {
		vfree(*target);
		*target = NULL;
	}
	mutex_unlock(&icap->icap_lock);
	vfree(copy_buffer);
	ICAP_INFO(icap, "%s kind %d, err: %ld", __FUNCTION__, kind, err);
	return err;
}

void *icap_get_axlf_section_data(struct platform_device *pdev,
	enum axlf_section_kind kind)
{

	struct icap *icap = platform_get_drvdata(pdev);
	void *target = NULL;

	mutex_lock(&icap->icap_lock);
	switch(kind){
		case IP_LAYOUT:
			target = icap->ip_layout;
			break;
		case MEM_TOPOLOGY:
			target = icap->mem_topo;
			break;
		case DEBUG_IP_LAYOUT:
			target = icap->debug_layout;
			break;
		case CONNECTIVITY:
			target = icap->connectivity;
			break;
		default:
			break;
	}
	mutex_unlock(&icap->icap_lock);
	return target;
}

/* Kernel APIs exported from this sub-device driver. */
static struct xocl_icap_funcs icap_ops = {
	.reset_axi_gate = platform_reset_axi_gate,
	.reset_bitstream = icap_reset_bitstream,
	.download_boot_firmware = icap_download_boot_firmware,
	.download_bitstream_axlf = icap_download_bitstream_axlf,
	.ocl_set_freq = icap_ocl_set_freqscaling,
	.ocl_get_freq = icap_ocl_get_freqscaling,
	.ocl_update_clock_freq_topology = icap_ocl_update_clock_freq_topology,
	.ocl_lock_bitstream = icap_lock_bitstream,
	.ocl_unlock_bitstream = icap_unlock_bitstream,
	.parse_axlf_section = icap_parse_bitstream_axlf_section,
	.get_axlf_section_data = icap_get_axlf_section_data,
};

static ssize_t clock_freq_topology_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct icap *icap = platform_get_drvdata(to_platform_device(dev));
	ssize_t cnt = 0;

	mutex_lock(&icap->icap_lock);
	memcpy(buf, icap->icap_clock_freq_topology, icap->icap_clock_freq_topology_length);
	cnt = icap->icap_clock_freq_topology_length;
	mutex_unlock(&icap->icap_lock);

	return cnt;

}

static DEVICE_ATTR_RO(clock_freq_topology);

static ssize_t clock_freqs_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct icap *icap = platform_get_drvdata(to_platform_device(dev));
	ssize_t cnt = 0;
	int i;
	u32 freq_counter, freq, request_in_khz, tolerance;

	mutex_lock(&icap->icap_lock);
	for (i = 0; i < ICAP_MAX_NUM_CLOCKS; i++) {
		freq = icap_get_ocl_frequency(icap, i);
		if(!uuid_is_null(&icap->icap_bitstream_uuid)){
			freq_counter = icap_get_clock_frequency_counter_khz(icap, i);

			request_in_khz =freq*1000;
			tolerance = freq*50;

			if(abs(freq_counter-request_in_khz)>tolerance)
				ICAP_INFO(icap, "Frequency mismatch, Should be %u khz, Now is %ukhz", request_in_khz, freq_counter);
			cnt += sprintf(buf + cnt, "%d\n", DIV_ROUND_CLOSEST(freq_counter,1000));
		}
		else{
			cnt += sprintf(buf + cnt, "%d\n", freq);
		}
	}

	mutex_unlock(&icap->icap_lock);

	return cnt;
}
static DEVICE_ATTR_RO(clock_freqs);

#ifdef SYSFS_DEBUG
static ssize_t icap_data_write(struct file *filp, struct kobject *kobj,
	struct bin_attribute *attr, char *buffer, loff_t off, size_t count)
{
	XHwIcap_Bit_Header bit_header = { 0 };
	struct device *dev = container_of(kobj, struct device, kobj);
	struct icap *icap = platform_get_drvdata(to_platform_device(dev));
	xdev_handle_t xdev = xocl_get_xdev(icap->icap_pdev);
	ssize_t ret = count;

	if (off == 0) {
		if (count < DMA_HWICAP_BITFILE_BUFFER_SIZE) {
			ICAP_ERR(icap, "count is too small %ld", count);
			return -EINVAL;
		}

		if (bitstream_parse_header(icap, buffer,
			DMA_HWICAP_BITFILE_BUFFER_SIZE, &bit_header)) {
			ICAP_ERR(icap, "parse header failed");
			return -EINVAL;
		}

		icap->bit_length = bit_header.HeaderLength +
			bit_header.BitstreamLength;
		icap->bit_buffer = vmalloc(icap->bit_length);
	}

	if (off + count >= icap->bit_length) {
		/*
 		 * TODO:
 		 * Need to Suspend mgmtpf/userpf and uninstall subdevices
		 */
		memcpy(icap->bit_buffer + off, buffer, icap->bit_length - off);
		ret = health_thread_stop(xdev);
		if (ret) {
			ICAP_ERR(icap, "stop health thread failed");
			goto failed;
		}
		//xocl_mb_stop(xdev);
		//reset_dma(icap, true);
		icap_freeze_axi_gate(icap, GATE_FREEZE_SHELL); 
		ret = icap_download(icap, icap->bit_buffer, icap->bit_length);
		if (ret) {
			ICAP_ERR(icap, "bitstream download failed");
			ret = -EIO;
		}
		icap_free_axi_gate(icap, gate_free_shell); 
		//reset_dma(icap, false);
		icap->icap_bitstream_id = 0;
		// xocl_mb_reset(xdev);
		ret = health_thread_start(xdev);
		if (ret) {
			ICAP_ERR(icap, "restart health thread failed");
		}
		vfree(icap->bit_buffer);
		icap->bit_buffer = NULL;
	} else {
		memcpy(icap->bit_buffer + off, buffer, count);
	}

	return count;

failed:
	return ret;
}

static struct bin_attribute bit_program_attr = {
	.attr = {
		.name = "bit_program",
		.mode = 0200
	},
	.read = NULL,
	.write = icap_data_write,
	.size = 0
};

static struct bin_attribute *icap_mgmt_bin_attrs[] = {
	&bit_program_attr,
	NULL,
};

static struct attribute_group icap_debug_attr_group = {
	.bin_attrs = icap_mgmt_bin_attrs,
};
#endif

static ssize_t idcode_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct icap *icap = platform_get_drvdata(to_platform_device(dev));
	return sprintf(buf, "0x%x\n", icap->idcode);
}

static DEVICE_ATTR_RO(idcode);

static struct attribute *icap_attrs[] = {
	&dev_attr_clock_freq_topology.attr,
	&dev_attr_clock_freqs.attr,
	&dev_attr_idcode.attr,
	NULL,
};

//- Debug IP_layout--
static ssize_t icap_read_debug_ip_layout(struct file *filp, struct kobject *kobj,
	struct bin_attribute *attr, char *buffer, loff_t offset, size_t count)
{
	struct icap *icap;
	u32 nread = 0;
	size_t size = 0;

	icap = (struct icap *)dev_get_drvdata(container_of(kobj, struct device, kobj));

	if(!icap || !icap->debug_layout)
		return 0;

	mutex_lock(&icap->icap_lock);

	size = sizeof_sect(icap->debug_layout, m_debug_ip_data);
	if (offset >= size)
		goto unlock;

	if (count < size - offset)
		nread = count;
	else
		nread = size - offset;

	memcpy(buffer, ((char *)icap->debug_layout) + offset, nread);

unlock:
	mutex_unlock(&icap->icap_lock);
	return nread;
}
static struct bin_attribute debug_ip_layout_attr = {
	.attr = {
		.name = "debug_ip_layout",
		.mode = 0444
	},
	.read = icap_read_debug_ip_layout,
	.write = NULL,
	.size = 0
};

//IP layout
static ssize_t icap_read_ip_layout(struct file *filp, struct kobject *kobj,
	struct bin_attribute *attr, char *buffer, loff_t offset, size_t count)
{
	struct icap *icap;
	u32 nread = 0;
	size_t size = 0;

	icap = (struct icap *)dev_get_drvdata(container_of(kobj, struct device, kobj));

	if(!icap || !icap->ip_layout)
		return 0;

	mutex_lock(&icap->icap_lock);

	size = sizeof_sect(icap->ip_layout, m_ip_data);
	if (offset >= size)
		goto unlock;

	if (count < size - offset)
		nread = count;
	else
		nread = size - offset;

	memcpy(buffer, ((char *)icap->ip_layout) + offset, nread);

unlock:
	mutex_unlock(&icap->icap_lock);
	return nread;
}

static struct bin_attribute ip_layout_attr = {
	.attr = {
		.name = "ip_layout",
		.mode = 0444
	},
	.read = icap_read_ip_layout,
	.write = NULL,
	.size = 0
};

//-Connectivity--
static ssize_t icap_read_connectivity(struct file *filp, struct kobject *kobj,
	struct bin_attribute *attr, char *buffer, loff_t offset, size_t count)
{
	struct icap *icap;
	u32 nread = 0;
	size_t size = 0;

	icap = (struct icap *)dev_get_drvdata(container_of(kobj, struct device, kobj));

	if(!icap || !icap->connectivity)
		return 0;

	mutex_lock(&icap->icap_lock);

	size = sizeof_sect(icap->connectivity, m_connection);
	if (offset >= size)
		goto unlock;

	if (count < size - offset)
		nread = count;
	else
		nread = size - offset;

	memcpy(buffer, ((char *)icap->connectivity) + offset, nread);

unlock:
	mutex_unlock(&icap->icap_lock);
	return nread;
}

static struct bin_attribute connectivity_attr = {
	.attr = {
		.name = "connectivity",
		.mode = 0444
	},
	.read = icap_read_connectivity,
	.write = NULL,
	.size = 0
};


//-Mem_topology--
static ssize_t icap_read_mem_topology(struct file *filp, struct kobject *kobj,
	struct bin_attribute *attr, char *buffer, loff_t offset, size_t count)
{
	struct icap *icap;
	u32 nread = 0;
	size_t size = 0;

	icap = (struct icap *)dev_get_drvdata(container_of(kobj, struct device, kobj));

	if(!icap || !icap->mem_topo)
		return 0;

	mutex_lock(&icap->icap_lock);

	size = sizeof_sect(icap->mem_topo, m_mem_data);
	if (offset >= size)
		goto unlock;

	if (count < size - offset)
		nread = count;
	else
		nread = size - offset;

	memcpy(buffer, ((char *)icap->mem_topo) + offset, nread);
unlock:
	mutex_unlock(&icap->icap_lock);
	return nread;
}


static struct bin_attribute mem_topology_attr = {
	.attr = {
		.name = "mem_topology",
		.mode = 0444
	},
	.read = icap_read_mem_topology,
	.write = NULL,
	.size = 0
};

static struct bin_attribute *icap_bin_attrs[] = {
	&debug_ip_layout_attr,
	&ip_layout_attr,
	&connectivity_attr,
	&mem_topology_attr,
	NULL,
};

static struct attribute_group icap_attr_group = {
	.attrs = icap_attrs,
	.bin_attrs = icap_bin_attrs,
};

static int icap_remove(struct platform_device *pdev)
{
	struct icap *icap = platform_get_drvdata(pdev);
	int i;

	BUG_ON(icap == NULL);

	del_all_users(icap);
	xocl_subdev_register(pdev, XOCL_SUBDEV_ICAP, NULL);

#ifdef SYSFS_DEBUG
	if (ICAP_PRIVILEGED(icap))
		sysfs_remove_group(&pdev->dev.kobj, &icap_debug_attr_group);

	if (icap->bit_buffer)
		vfree(icap->bit_buffer);
#endif

	iounmap(icap->icap_regs);
	iounmap(icap->icap_state);
	iounmap(icap->icap_axi_gate);
	for (i = 0; i < ICAP_MAX_NUM_CLOCKS; i++)
		iounmap(icap->icap_clock_bases[i]);
	free_clear_bitstream(icap);
	free_clock_freq_topology(icap);

	sysfs_remove_group(&pdev->dev.kobj, &icap_attr_group);

	ICAP_INFO(icap, "cleaned up successfully");
	platform_set_drvdata(pdev, NULL);
	vfree(icap->mem_topo);
	vfree(icap->ip_layout);
	vfree(icap->debug_layout);
	vfree(icap->connectivity);
	kfree(icap);
	return 0;
}

/*
 * Run the following sequence of canned commands to obtain IDCODE of the FPGA
 */
static void icap_probe_chip(struct icap *icap)
{
	u32 w;

	if (!ICAP_PRIVILEGED(icap))
		return;

	w = reg_rd(&icap->icap_regs->ir_sr);
	w = reg_rd(&icap->icap_regs->ir_sr);
	reg_wr(&icap->icap_regs->ir_gier, 0x0);
	w = reg_rd(&icap->icap_regs->ir_wfv);
	reg_wr(&icap->icap_regs->ir_wf, 0xffffffff);
	reg_wr(&icap->icap_regs->ir_wf, 0xaa995566);
	reg_wr(&icap->icap_regs->ir_wf, 0x20000000);
	reg_wr(&icap->icap_regs->ir_wf, 0x20000000);
	reg_wr(&icap->icap_regs->ir_wf, 0x28018001);
	reg_wr(&icap->icap_regs->ir_wf, 0x20000000);
	reg_wr(&icap->icap_regs->ir_wf, 0x20000000);
	w = reg_rd(&icap->icap_regs->ir_cr);
	reg_wr(&icap->icap_regs->ir_cr, 0x1);
	w = reg_rd(&icap->icap_regs->ir_cr);
	w = reg_rd(&icap->icap_regs->ir_cr);
	w = reg_rd(&icap->icap_regs->ir_sr);
	w = reg_rd(&icap->icap_regs->ir_cr);
	w = reg_rd(&icap->icap_regs->ir_sr);
	reg_wr(&icap->icap_regs->ir_sz, 0x1);
	w = reg_rd(&icap->icap_regs->ir_cr);
	reg_wr(&icap->icap_regs->ir_cr, 0x2);
	w = reg_rd(&icap->icap_regs->ir_rfo);
	icap->idcode = reg_rd(&icap->icap_regs->ir_rf);
	w = reg_rd(&icap->icap_regs->ir_cr);
}

static int icap_probe(struct platform_device *pdev)
{
	struct icap *icap = NULL;
	struct resource *res;
	int ret;
	int reg_grp;
	void **regs;

	icap = kzalloc(sizeof(struct icap), GFP_KERNEL);
	if (!icap)
		return -ENOMEM;
	platform_set_drvdata(pdev, icap);
	icap->icap_pdev = pdev;
	mutex_init(&icap->icap_lock);
	INIT_LIST_HEAD(&icap->icap_bitstream_users);

	for (reg_grp = 0; reg_grp < ICAP_MAX_REG_GROUPS; reg_grp++) {
		switch (reg_grp) {
		case 0:
			regs = (void **)&icap->icap_regs;
			break;
		case 1:
			regs = (void **)&icap->icap_state;
			break;
		case 2:
			regs = (void **)&icap->icap_axi_gate;
			break;
		case 3:
			regs = (void **)&icap->icap_clock_bases[0];
			break;
		case 4:
			regs = (void **)&icap->icap_clock_bases[1];
			break;
		case 5:
			regs = (void **)&icap->icap_clock_freq_counter;
			break;
		default:
			BUG();
			break;
		}
		res = platform_get_resource(pdev, IORESOURCE_MEM, reg_grp);
		if (res != NULL) {
			*regs = ioremap_nocache(res->start,
				res->end - res->start + 1);
			if (*regs == NULL) {
				ICAP_ERR(icap,
					"failed to map in register group: %d",
					reg_grp);
				ret = -EIO;
				goto failed;
			} else {
				ICAP_INFO(icap,
					"mapped in register group %d @ 0x%p",
					reg_grp, *regs);
			}
		} else {
			if (reg_grp != 0) {
				ICAP_ERR(icap,
					"failed to find register group: %d",
					reg_grp);
				ret = -EIO;
				goto failed;
			}
			break;
		}
	}

	ret = sysfs_create_group(&pdev->dev.kobj, &icap_attr_group);
	if (ret) {
		ICAP_ERR(icap, "create icap attrs failed: %d", ret);
		goto failed;
	}

#ifdef SYSFS_DEBUG
	if (ICAP_PRIVILEGED(icap)) {
		ret = sysfs_create_group(&pdev->dev.kobj,
			&icap_debug_attr_group);
		if (ret) {
			ICAP_ERR(icap, "create icap attrs failed: %d", ret);
			goto failed;
		}
	}
#endif

	icap_probe_chip(icap);
	ICAP_INFO(icap, "successfully initialized FPGA IDCODE 0x%x", icap->idcode);
	xocl_subdev_register(pdev, XOCL_SUBDEV_ICAP, &icap_ops);
	return 0;

failed:
	(void) icap_remove(pdev);
	return ret;
}


struct platform_device_id icap_id_table[] = {
	{ XOCL_ICAP, 0 },
	{ },
};

static struct platform_driver icap_driver = {
	.probe		= icap_probe,
	.remove		= icap_remove,
	.driver		= {
		.name	= XOCL_ICAP,
	},
	.id_table = icap_id_table,
};

int __init xocl_init_icap(void)
{
	return platform_driver_register(&icap_driver);
}

void xocl_fini_icap(void)
{
	platform_driver_unregister(&icap_driver);
}
