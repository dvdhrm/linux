/*
 * SimpleDRM firmware framebuffer driver
 * Copyright (c) 2012-2013 David Herrmann <dh.herrmann@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#include <linux/errno.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/platform_data/simplefb.h>
#include <linux/string.h>
#include <drm/drmP.h>
#include "simpledrm.h"

static const struct file_operations sdrm_drm_fops = {
	.owner = THIS_MODULE,
	.open = drm_open,
	.mmap = sdrm_drm_mmap,
	.poll = drm_poll,
	.read = drm_read,
	.unlocked_ioctl = drm_ioctl,
	.release = drm_release,
#ifdef CONFIG_COMPAT
	.compat_ioctl = drm_compat_ioctl,
#endif
	.llseek = noop_llseek,
};

static struct drm_driver sdrm_drm_driver = {
	.driver_features = DRIVER_MODESET | DRIVER_GEM,
	.load = sdrm_drm_load,
	.unload = sdrm_drm_unload,
	.fops = &sdrm_drm_fops,

	.gem_init_object = sdrm_gem_init_object,
	.gem_free_object = sdrm_gem_free_object,

	.dumb_create = sdrm_dumb_create,
	.dumb_map_offset = sdrm_dumb_map_offset,
	.dumb_destroy = sdrm_dumb_destroy,

	.name = "simpledrm",
	.desc = "Simple firmware framebuffer DRM driver",
	.date = "20130601",
	.major = 0,
	.minor = 0,
	.patchlevel = 1,
};

static int parse_dt(struct platform_device *pdev,
		    struct simplefb_platform_data *mode)
{
	struct device_node *np = pdev->dev.of_node;
	const char *format;
	int ret;

	if (!np)
		return -ENODEV;

	ret = of_property_read_u32(np, "width", &mode->width);
	if (ret) {
		dev_err(&pdev->dev, "Can't parse width property\n");
		return ret;
	}

	ret = of_property_read_u32(np, "height", &mode->height);
	if (ret) {
		dev_err(&pdev->dev, "Can't parse height property\n");
		return ret;
	}

	ret = of_property_read_u32(np, "stride", &mode->stride);
	if (ret) {
		dev_err(&pdev->dev, "Can't parse stride property\n");
		return ret;
	}

	ret = of_property_read_string(np, "format", &format);
	if (ret) {
		dev_err(&pdev->dev, "Can't parse format property\n");
		return ret;
	}
	mode->format = format;

	return 0;
}

static struct simplefb_format simplefb_formats[] = SIMPLEFB_FORMATS;

int sdrm_pdev_init(struct sdrm_device *sdrm)
{
	struct platform_device *pdev = sdrm->ddev->platformdev;
	struct simplefb_platform_data *mode = pdev->dev.platform_data;
	struct simplefb_platform_data pmode;
	struct resource *mem;
	unsigned int depth;
	int ret, i, bpp;

	if (!mode) {
		mode = &pmode;
		ret = parse_dt(pdev, mode);
		if (ret)
			return ret;
	}

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!mem) {
		dev_err(sdrm->ddev->dev, "No memory resource\n");
		return -ENODEV;
	}

	for (i = 0; i < ARRAY_SIZE(simplefb_formats); ++i) {
		if (strcmp(mode->format, simplefb_formats[i].name))
			continue;

		sdrm->fb_sformat = &simplefb_formats[i];
		sdrm->fb_format = simplefb_formats[i].fourcc;
		sdrm->fb_width = mode->width;
		sdrm->fb_height = mode->height;
		sdrm->fb_stride = mode->stride;
		sdrm->fb_base = mem->start;
		sdrm->fb_size = resource_size(mem);
		break;
	}

	if (i >= ARRAY_SIZE(simplefb_formats)) {
		dev_err(sdrm->ddev->dev, "Unknown format %s\n", mode->format);
		return -ENODEV;
	}

	drm_fb_get_bpp_depth(sdrm->fb_format, &depth, &bpp);
	if (!bpp) {
		dev_err(sdrm->ddev->dev, "Unknown format %s\n", mode->format);
		return -ENODEV;
	}

	if (sdrm->fb_size < sdrm->fb_stride * sdrm->fb_height) {
		dev_err(sdrm->ddev->dev, "FB too small\n");
		return -ENODEV;
	} else if ((bpp + 7) / 8 * sdrm->fb_width > sdrm->fb_stride) {
		dev_err(sdrm->ddev->dev, "Invalid stride\n");
		return -ENODEV;
	}

	sdrm->fb_bpp = bpp;

	if (!request_mem_region(sdrm->fb_base, sdrm->fb_size,
				"simple-framebuffer")) {
		dev_err(sdrm->ddev->dev, "cannot reserve VMEM\n");
		return -EIO;
	}

	sdrm->fb_map = ioremap_wc(sdrm->fb_base, sdrm->fb_size);
	if (!sdrm->fb_map) {
		dev_err(sdrm->ddev->dev, "cannot remap VMEM\n");
		ret = -EIO;
		goto err_region;
	}

	return 0;

err_region:
	release_mem_region(sdrm->fb_base, sdrm->fb_size);
	return ret;
}

void sdrm_pdev_destroy(struct sdrm_device *sdrm)
{
	if (sdrm->fb_map) {
		iounmap(sdrm->fb_map);
		release_mem_region(sdrm->fb_base, sdrm->fb_size);
		sdrm->fb_map = NULL;
	}
}

static int sdrm_simplefb_probe(struct platform_device *pdev)
{
	return drm_platform_init(&sdrm_drm_driver, pdev);
}

static int sdrm_simplefb_remove(struct platform_device *pdev)
{
	drm_platform_exit(&sdrm_drm_driver, pdev);

	return 0;
}

static const struct of_device_id simplefb_of_match[] = {
	{ .compatible = "simple-framebuffer", },
	{ },
};
MODULE_DEVICE_TABLE(of, simplefb_of_match);

static struct platform_driver sdrm_simplefb_driver = {
	.probe = sdrm_simplefb_probe,
	.remove = sdrm_simplefb_remove,
	.driver = {
		.name = "simple-framebuffer",
		.mod_name = KBUILD_MODNAME,
		.owner = THIS_MODULE,
		.of_match_table = simplefb_of_match,
	},
};

static int __init sdrm_init(void)
{
	return platform_driver_register(&sdrm_simplefb_driver);
}

static void __exit sdrm_exit(void)
{
	platform_driver_unregister(&sdrm_simplefb_driver);
}

module_init(sdrm_init);
module_exit(sdrm_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("David Herrmann <dh.herrmann@gmail.com>");
MODULE_DESCRIPTION("Simple firmware framebuffer DRM driver");
