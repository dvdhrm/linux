/*
 * SimpleDRM firmware framebuffer driver
 * Copyright (c) 2012-2013 David Herrmann <dh.herrmann@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#ifndef SDRM_DRV_H
#define SDRM_DRV_H

#include <linux/errno.h>
#include <linux/fb.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/platform_data/simplefb.h>
#include <linux/string.h>
#include <drm/drmP.h>

struct sdrm_device;
struct sdrm_gem_object;
struct sdrm_framebuffer;

/* simpledrm devices */

struct sdrm_device {
	struct drm_device *ddev;

	/* framebuffer information */
	const struct simplefb_format *fb_sformat;
	u32 fb_format;
	u32 fb_width;
	u32 fb_height;
	u32 fb_stride;
	u32 fb_bpp;
	unsigned long fb_base;
	unsigned long fb_size;
	void *fb_map;

	/* mode-setting objects */
	struct sdrm_gem_object *fb_obj;
	struct drm_crtc crtc;
	struct drm_encoder enc;
	struct drm_connector conn;
	struct drm_display_mode *mode;

	/* fbdev */
	struct fb_info *fbdev;
};

int sdrm_drm_load(struct drm_device *ddev, unsigned long flags);
int sdrm_drm_unload(struct drm_device *ddev);
int sdrm_drm_mmap(struct file *filp, struct vm_area_struct *vma);
int sdrm_pdev_init(struct sdrm_device *sdrm);
void sdrm_pdev_destroy(struct sdrm_device *sdrm);

/* simpledrm gem objects */

struct sdrm_gem_object {
	struct drm_gem_object base;
	unsigned long fb_base;
	unsigned long fb_size;
};

#define to_sdrm_bo(x) container_of(x, struct sdrm_gem_object, base)

int sdrm_gem_init_object(struct drm_gem_object *obj);
void sdrm_gem_free_object(struct drm_gem_object *obj);
void sdrm_gem_unmap_object(struct sdrm_gem_object *obj);

/* dumb buffers */

int sdrm_dumb_create(struct drm_file *file_priv, struct drm_device *ddev,
		     struct drm_mode_create_dumb *arg);
int sdrm_dumb_destroy(struct drm_file *file_priv, struct drm_device *ddev,
		      uint32_t handle);
int sdrm_dumb_map_offset(struct drm_file *file_priv, struct drm_device *ddev,
			 uint32_t handle, uint64_t *offset);

/* simpledrm framebuffers */

struct sdrm_framebuffer {
	struct drm_framebuffer base;
	struct sdrm_gem_object *obj;
};

#define to_sdrm_fb(x) container_of(x, struct sdrm_framebuffer, base)

/* simpledrm fbdev helpers */

#ifdef CONFIG_DRM_SIMPLEDRM_FBDEV

void sdrm_fbdev_init(struct sdrm_device *sdrm);
void sdrm_fbdev_cleanup(struct sdrm_device *sdrm);

#else /* CONFIG_DRM_SIMPLEDRM_FBDEV */

static inline void sdrm_fbdev_init(struct sdrm_device *sdrm)
{
}

static inline void sdrm_fbdev_cleanup(struct sdrm_device *sdrm)
{
}

#endif /* CONFIG_DRM_SIMPLEDRM_FBDEV */

#endif /* SDRM_DRV_H */
