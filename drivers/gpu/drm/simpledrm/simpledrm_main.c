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
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/string.h>
#include <drm/drmP.h>
#include <drm/drm_crtc.h>
#include "simpledrm.h"

/* crtcs */

static int sdrm_crtc_set_config(struct drm_mode_set *set)
{
	struct drm_device *ddev;
	struct sdrm_device *sdrm;
	struct sdrm_framebuffer *fb;

	if (!set || !set->crtc)
		return -EINVAL;

	ddev = set->crtc->dev;
	sdrm = ddev->dev_private;

	if (set->crtc != &sdrm->crtc)
		return -EINVAL;

	if (!set->mode || !set->fb || !set->num_connectors) {
		sdrm->conn.encoder = NULL;
		sdrm->conn.dpms = DRM_MODE_DPMS_OFF;
		sdrm->enc.crtc = NULL;
		sdrm->crtc.fb = NULL;
		sdrm->crtc.enabled = false;
		return 0;
	}

	fb = to_sdrm_fb(set->fb);

	if (set->num_connectors != 1 || set->connectors[0] != &sdrm->conn)
		return -EINVAL;
	if (set->x || set->y)
		return -EINVAL;
	if (set->mode->hdisplay != sdrm->fb_width ||
	    set->mode->vdisplay != sdrm->fb_height)
		return -EINVAL;

	sdrm->conn.encoder = &sdrm->enc;
	sdrm->conn.dpms = DRM_MODE_DPMS_ON;
	sdrm->enc.crtc = &sdrm->crtc;
	sdrm->crtc.fb = set->fb;
	sdrm->crtc.enabled = true;
	sdrm->crtc.mode = *set->mode;
	sdrm->crtc.hwmode = *set->mode;
	sdrm->crtc.x = 0;
	sdrm->crtc.y = 0;

	drm_calc_timestamping_constants(&sdrm->crtc);
	return 0;
}

static const struct drm_crtc_funcs sdrm_crtc_ops = {
	.set_config = sdrm_crtc_set_config,
	.destroy = drm_crtc_cleanup,
};

/* encoders */

static const struct drm_encoder_funcs sdrm_enc_ops = {
	.destroy = drm_encoder_cleanup,
};

/* connectors */

static void sdrm_conn_dpms(struct drm_connector *conn, int mode)
{
	conn->dpms = mode;
}

static enum drm_connector_status sdrm_conn_detect(struct drm_connector *conn,
						  bool force)
{
	/* We simulate an always connected monitor. simple-fb doesn't
	 * provide any way to detect whether the connector is active. Hence,
	 * signal DRM core that it is always connected. */

	return connector_status_connected;
}

static int sdrm_conn_fill_modes(struct drm_connector *conn, uint32_t max_x,
				uint32_t max_y)
{
	struct sdrm_device *sdrm = conn->dev->dev_private;
	struct drm_display_mode *mode;
	int ret;

	if (conn->force == DRM_FORCE_ON)
		conn->status = connector_status_connected;
	else if (conn->force)
		conn->status = connector_status_disconnected;
	else
		conn->status = connector_status_connected;

	list_for_each_entry(mode, &conn->modes, head)
		mode->status = MODE_UNVERIFIED;

	mode = drm_gtf_mode(sdrm->ddev, sdrm->fb_width, sdrm->fb_height,
			    60, 0, 0);
	if (mode) {
		mode->type = DRM_MODE_TYPE_DRIVER | DRM_MODE_TYPE_PREFERRED;
		drm_mode_probed_add(conn, mode);
		sdrm->mode = mode;
		drm_mode_connector_list_update(conn);
		ret = 1;
	} else {
		ret = 0;
	}

	if (max_x && max_y)
		drm_mode_validate_size(conn->dev, &conn->modes,
				       max_x, max_y, 0);

	drm_mode_prune_invalid(conn->dev, &conn->modes, false);
	if (list_empty(&conn->modes))
		return 0;

	drm_mode_sort(&conn->modes);

	list_for_each_entry(mode, &conn->modes, head) {
		mode->vrefresh = drm_mode_vrefresh(mode);
		drm_mode_set_crtcinfo(mode, CRTC_INTERLACE_HALVE_V);
	}

	return ret;
}

static void sdrm_conn_destroy(struct drm_connector *conn)
{
	/* Remove the fake-connector from sysfs and then let the DRM core
	 * clean up all associated resources. */
	if (device_is_registered(&conn->kdev))
		drm_sysfs_connector_remove(conn);
	drm_connector_cleanup(conn);
}

static const struct drm_connector_funcs sdrm_conn_ops = {
	.dpms = sdrm_conn_dpms,
	.detect = sdrm_conn_detect,
	.fill_modes = sdrm_conn_fill_modes,
	.destroy = sdrm_conn_destroy,
};

/* framebuffers */

static int sdrm_fb_create_handle(struct drm_framebuffer *fb,
				 struct drm_file *dfile,
				 unsigned int *handle)
{
	struct sdrm_framebuffer *sfb = to_sdrm_fb(fb);

	return drm_gem_handle_create(dfile, &sfb->obj->base, handle);
}

static void sdrm_fb_destroy(struct drm_framebuffer *fb)
{
	struct sdrm_framebuffer *sfb = to_sdrm_fb(fb);

	drm_framebuffer_cleanup(fb);
	drm_gem_object_unreference_unlocked(&sfb->obj->base);
	kfree(sfb);
}

static const struct drm_framebuffer_funcs sdrm_fb_ops = {
	.create_handle = sdrm_fb_create_handle,
	.destroy = sdrm_fb_destroy,
};

static struct drm_framebuffer *sdrm_fb_create(struct drm_device *ddev,
					      struct drm_file *dfile,
					      struct drm_mode_fb_cmd2 *cmd)
{
	struct sdrm_device *sdrm = ddev->dev_private;
	struct sdrm_framebuffer *fb;
	struct drm_gem_object *gobj;
	int ret, i;
	void *err;

	if (cmd->flags || cmd->pixel_format != sdrm->fb_format)
		return ERR_PTR(-EINVAL);
	if (cmd->height != sdrm->fb_height || cmd->width != sdrm->fb_width)
		return ERR_PTR(-EINVAL);
	if (cmd->offsets[0] || cmd->pitches[0] != sdrm->fb_stride)
		return ERR_PTR(-EINVAL);

	gobj = drm_gem_object_lookup(ddev, dfile, cmd->handles[0]);
	if (!gobj)
		return ERR_PTR(-EINVAL);

	fb = kzalloc(sizeof(*fb), GFP_KERNEL);
	if (!fb) {
		err = ERR_PTR(-ENOMEM);
		goto err_unref;
	}
	fb->obj = to_sdrm_bo(gobj);

	fb->base.pitches[0] = cmd->pitches[0];
	fb->base.offsets[0] = cmd->offsets[0];
	for (i = 1; i < 4; i++) {
		fb->base.pitches[i] = 0;
		fb->base.offsets[i] = 0;
	}

	fb->base.width = cmd->width;
	fb->base.height = cmd->height;
	fb->base.pixel_format = cmd->pixel_format;
	drm_fb_get_bpp_depth(cmd->pixel_format, &fb->base.depth,
			     &fb->base.bits_per_pixel);

	ret = drm_framebuffer_init(ddev, &fb->base, &sdrm_fb_ops);
	if (ret < 0) {
		err = ERR_PTR(ret);
		goto err_free;
	}

	return &fb->base;

err_free:
	kfree(fb);
err_unref:
	drm_gem_object_unreference_unlocked(gobj);
	return err;
}

static const struct drm_mode_config_funcs sdrm_mode_config_ops = {
	.fb_create = sdrm_fb_create,
};

/* initialization */

int sdrm_drm_load(struct drm_device *ddev, unsigned long flags)
{
	struct sdrm_device *sdrm;
	int ret;

	sdrm = kzalloc(sizeof(*sdrm), GFP_KERNEL);
	if (!sdrm)
		return -ENOMEM;

	sdrm->ddev = ddev;
	ddev->dev_private = sdrm;

	ddev->devname = kstrdup("simpledrm", GFP_KERNEL);
	if (!ddev->devname) {
		ret = -ENOMEM;
		goto err_free;
	}

	ret = sdrm_pdev_init(sdrm);
	if (ret)
		goto err_name;

	drm_mode_config_init(ddev);
	ddev->mode_config.min_width = 0;
	ddev->mode_config.min_height = 0;
	ddev->mode_config.max_width = 8192;
	ddev->mode_config.max_height = 8192;
	ddev->mode_config.funcs = &sdrm_mode_config_ops;

	ret = drm_crtc_init(ddev, &sdrm->crtc, &sdrm_crtc_ops);
	if (ret)
		goto err_cleanup;

	sdrm->enc.possible_crtcs = 1;
	sdrm->enc.possible_clones = 0;
	ret = drm_encoder_init(ddev, &sdrm->enc, &sdrm_enc_ops,
			       DRM_MODE_ENCODER_VIRTUAL);
	if (ret)
		goto err_cleanup;

	sdrm->conn.display_info.width_mm = 0;
	sdrm->conn.display_info.height_mm = 0;
	sdrm->conn.interlace_allowed = false;
	sdrm->conn.doublescan_allowed = false;
	sdrm->conn.polled = 0;
	ret = drm_connector_init(ddev, &sdrm->conn, &sdrm_conn_ops,
				 DRM_MODE_CONNECTOR_VIRTUAL);
	if (ret)
		goto err_cleanup;

	ret = drm_mode_connector_attach_encoder(&sdrm->conn, &sdrm->enc);
	if (ret)
		goto err_cleanup;

	ret = drm_sysfs_connector_add(&sdrm->conn);
	if (ret)
		goto err_cleanup;

	sdrm_fbdev_init(sdrm);
	return 0;

err_cleanup:
	drm_mode_config_cleanup(ddev);
	sdrm_pdev_destroy(sdrm);
err_name:
	kfree(ddev->devname);
	ddev->devname = NULL;
err_free:
	kfree(sdrm);
	return ret;
}

int sdrm_drm_unload(struct drm_device *ddev)
{
	struct sdrm_device *sdrm = ddev->dev_private;

	sdrm_fbdev_cleanup(sdrm);
	drm_mode_config_cleanup(ddev);
	sdrm_pdev_destroy(sdrm);
	kfree(sdrm);

	return 0;
}
