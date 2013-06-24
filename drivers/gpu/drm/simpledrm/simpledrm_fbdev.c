/*
 * SimpleDRM firmware framebuffer driver
 * Copyright (c) 2012-2013 David Herrmann <dh.herrmann@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

/*
 * fbdev compatibility layer
 * We provide a basic fbdev device for the same framebuffer that is used for
 * the pseudo CRTC.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/fb.h>
#include "simpledrm.h"

struct sdrm_fbdev {
	u32 palette[16];
};

static int sdrm_fbdev_setcolreg(u_int regno, u_int red, u_int green,
				u_int blue, u_int transp, struct fb_info *info)
{
	u32 *pal = info->pseudo_palette;
	u32 cr = red >> (16 - info->var.red.length);
	u32 cg = green >> (16 - info->var.green.length);
	u32 cb = blue >> (16 - info->var.blue.length);
	u32 value;

	if (regno >= 16)
		return -EINVAL;

	value = (cr << info->var.red.offset) |
		(cg << info->var.green.offset) |
		(cb << info->var.blue.offset);

	if (info->var.transp.length > 0) {
		u32 mask = (1 << info->var.transp.length) - 1;
		mask <<= info->var.transp.offset;
		value |= mask;
	}

	pal[regno] = value;

	return 0;
}

static struct fb_ops sdrm_fbdev_ops = {
	.owner		= THIS_MODULE,
	.fb_setcolreg	= sdrm_fbdev_setcolreg,
	.fb_fillrect	= cfb_fillrect,
	.fb_copyarea	= cfb_copyarea,
	.fb_imageblit	= cfb_imageblit,
};

void sdrm_fbdev_init(struct sdrm_device *sdrm)
{
	struct sdrm_fbdev *fb;
	struct fb_info *info;
	int ret;

	if (fb_get_options("simpledrmfb", NULL))
		return;

	info = framebuffer_alloc(sizeof(struct sdrm_fbdev), sdrm->ddev->dev);
	if (!info)
		goto err_out;

	fb = info->par;
	info->flags = FBINFO_DEFAULT | FBINFO_MISC_FIRMWARE;
	info->pseudo_palette = fb->palette;
	info->fbops = &sdrm_fbdev_ops;
	info->screen_base = sdrm->fb_map;

	strncpy(info->fix.id, "simpledrmfb", 15);
	info->fix.type = FB_TYPE_PACKED_PIXELS;
	info->fix.visual = FB_VISUAL_TRUECOLOR;
	info->fix.accel = FB_ACCEL_NONE;
	info->fix.smem_start = (unsigned long)sdrm->fb_base;
	info->fix.smem_len = sdrm->fb_size;
	info->fix.line_length = sdrm->fb_stride;

	info->var.activate = FB_ACTIVATE_NOW;
	info->var.vmode = FB_VMODE_NONINTERLACED;
	info->var.bits_per_pixel = sdrm->fb_bpp;
	info->var.height = -1;
	info->var.width = -1;
	info->var.xres = sdrm->fb_width;
	info->var.yres = sdrm->fb_height;
	info->var.xres_virtual = info->var.xres;
	info->var.yres_virtual = info->var.yres;
	info->var.red = sdrm->fb_sformat->red;
	info->var.green = sdrm->fb_sformat->green;
	info->var.blue = sdrm->fb_sformat->blue;
	info->var.transp = sdrm->fb_sformat->transp;

	/* some dummy values for timing to make fbset happy */
	info->var.pixclock = 10000000 / info->var.xres * 1000 / info->var.yres;
	info->var.left_margin = (info->var.xres / 8) & 0xf8;
	info->var.right_margin = 32;
	info->var.upper_margin = 16;
	info->var.lower_margin = 4;
	info->var.hsync_len = (info->var.xres / 8) & 0xf8;
	info->var.vsync_len = 4;

	info->apertures = alloc_apertures(1);
	if (!info->apertures)
		goto err_free;

	info->apertures->ranges[0].base = (unsigned long)sdrm->fb_base;
	info->apertures->ranges[0].size = sdrm->fb_size;

	sdrm->fbdev = info;
	ret = register_framebuffer(info);
	if (ret < 0)
		goto err_free;

	dev_info(sdrm->ddev->dev, "fbdev frontend %s as fb%d\n",
		 info->fix.id, info->node);

	return;

err_free:
	framebuffer_release(info);
	sdrm->fbdev = NULL;
err_out:
	dev_warn(sdrm->ddev->dev, "cannot create fbdev frontend\n");
}

void sdrm_fbdev_cleanup(struct sdrm_device *sdrm)
{
	struct fb_info *info;

	if (!sdrm->fbdev)
		return;

	dev_info(sdrm->ddev->dev, "fbdev cleanup\n");
	info = sdrm->fbdev;
	sdrm->fbdev = NULL;

	if (unregister_framebuffer(info))
		dev_warn(sdrm->ddev->dev, "unregister_framebuffer() failed, leaking fbdev device\n");
	else
		framebuffer_release(info);
}
