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
#include "simpledrm.h"

/*
 * Create GEM Object
 * Allocates a new GEM object to manage the physical memory at @fb_base with
 * size @fb_size. Both parameters must be page-aligned and point to the
 * physical memory of the framebuffer to manage. They must not have a
 * "struct page" and have to be reserved before.
 * It is the callers responsibility to create only one object per framebuffer.
 */
static struct sdrm_gem_object *sdrm_gem_alloc_object(struct drm_device *ddev,
						     unsigned long fb_base,
						     unsigned long fb_size)
{
	struct sdrm_gem_object *obj;

	WARN_ON((fb_base & ~PAGE_MASK) != 0);
	WARN_ON((fb_size & ~PAGE_MASK) != 0);

	/* align to page-size */
	fb_size = fb_size + (fb_base & ~PAGE_MASK);
	fb_base = fb_base & PAGE_MASK;
	fb_size = PAGE_ALIGN(fb_size);

	if (fb_base + fb_size < fb_base)
		return NULL;

	obj = kzalloc(sizeof(*obj), GFP_KERNEL);
	if (!obj)
		return NULL;
	obj->fb_base = fb_base;
	obj->fb_size = fb_size;

	drm_gem_private_object_init(ddev, &obj->base, fb_size);

	return obj;
}

/* drm_gem_object_alloc() is not supported */
int sdrm_gem_init_object(struct drm_gem_object *gobj)
{
	return -EINVAL;
}

/*
 * Unmap GEM Object
 * Destroy any memory-mappings that user-space created on this object. Note
 * that this will cause SIGBUS errors if user-space continues writing to it.
 * There is no way to remap the pages in fault-handlers as this is not what
 * we want. You should destroy the mappings only when destroying the object
 * so no remapping will be needed.
 * It's the callers responsibility to prevent any further mappings. This only
 * destroys all current mappings.
 */
void sdrm_gem_unmap_object(struct sdrm_gem_object *obj)
{
	struct drm_device *ddev = obj->base.dev;

	drm_vma_node_unmap(&obj->base.vma_node, ddev->dev_mapping);
}

/*
 * Free GEM Object
 * Frees the given GEM object. It does not release the framebuffer memory that
 * was passed during allocation, but destroys all user-space mappings.
 */
void sdrm_gem_free_object(struct drm_gem_object *gobj)
{
	struct sdrm_gem_object *obj = to_sdrm_bo(gobj);
	struct drm_device *ddev = gobj->dev;
	struct sdrm_device *sdrm = ddev->dev_private;

	if (sdrm->fb_obj == obj)
		sdrm->fb_obj = NULL;

	sdrm_gem_unmap_object(obj);

	drm_gem_free_mmap_offset(gobj);
	drm_gem_object_release(gobj);
	kfree(obj);
}

/*
 * Create Dumb Buffer
 * IOCTL backend for dumb-buffers. We only support one framebuffer per
 * simple-DRM device so this function fails if there is already a framebuffer
 * allocated. If not, an initial GEM-object plus framebuffer is created and
 * forwarded to the caller.
 *
 * We could try to kill off the previous framebuffer and create a new one for
 * the caller. However, user-space often allocates two buffers in a row to
 * allow double-buffering. If we kill the previous buffer, user-space would
 * have no chance to notice that only one buffer is available.
 *
 * So user-space must make sure they either destroy their buffer when dropping
 * DRM-Master or leave the CRTC intact and let others share the buffer via
 * drmModeGetFB().
 *
 * The buffer parameters must be the same as from the default-mode of the CRTC.
 * No other sizes can be supported!
 */
int sdrm_dumb_create(struct drm_file *dfile, struct drm_device *ddev,
		     struct drm_mode_create_dumb *args)
{
	struct drm_device *dev = dfile->minor->dev;
	struct sdrm_device *sdrm = dev->dev_private;
	struct sdrm_gem_object *obj;
	int ret;

	/* only allow one framebuffer at a time */
	if (sdrm->fb_obj)
		return -ENOMEM;

	if (args->width != sdrm->fb_width ||
	    args->height != sdrm->fb_height ||
	    args->bpp != sdrm->fb_bpp ||
	    args->flags)
		return -EINVAL;

	args->pitch = sdrm->fb_stride;
	args->size = sdrm->fb_size;
	obj = sdrm_gem_alloc_object(ddev, sdrm->fb_base, sdrm->fb_size);
	if (!obj)
		return -ENOMEM;

	ret = drm_gem_handle_create(dfile, &obj->base, &args->handle);
	if (ret) {
		drm_gem_object_unreference(&obj->base);
		return ret;
	}

	/* fb_obj is cleared by sdrm_gem_free_object() */
	sdrm->fb_obj = obj;
	drm_gem_object_unreference(&obj->base);

	return 0;
}

int sdrm_dumb_destroy(struct drm_file *dfile, struct drm_device *ddev,
		      uint32_t handle)
{
	return drm_gem_handle_delete(dfile, handle);
}

int sdrm_dumb_map_offset(struct drm_file *dfile, struct drm_device *ddev,
			 uint32_t handle, uint64_t *offset)
{
	struct drm_gem_object *gobj;
	int ret;

	mutex_lock(&ddev->struct_mutex);

	gobj = drm_gem_object_lookup(ddev, dfile, handle);
	if (!gobj) {
		ret = -ENOENT;
		goto out_unlock;
	}

	ret = drm_gem_create_mmap_offset(gobj);
	if (ret)
		goto out_unref;

	*offset = drm_vma_node_offset_addr(&gobj->vma_node);

out_unref:
	drm_gem_object_unreference(gobj);
out_unlock:
	mutex_unlock(&ddev->struct_mutex);
	return ret;
}

/*
 * mmap ioctl
 * We simply map the physical range of the FB into user-space as requested. We
 * perform few sanity-checks and then let io_remap_pfn_range() do all the work.
 * No vma_ops are needed this way as pages are either cleared or present.
 */
int sdrm_drm_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct drm_file *priv = filp->private_data;
	struct drm_device *dev = priv->minor->dev;
	struct drm_gem_mm *mm = dev->mm_private;
	struct drm_vma_offset_node *node;
	struct drm_gem_object *gobj;
	struct sdrm_gem_object *obj;
	int ret;

	if (drm_device_is_unplugged(dev))
		return -ENODEV;

	mutex_lock(&dev->struct_mutex);

	node = drm_vma_offset_exact_lookup(&mm->vma_manager, vma->vm_pgoff,
					   vma_pages(vma));
	if (!node) {
		mutex_unlock(&dev->struct_mutex);
		return drm_mmap(filp, vma);
	} else if (!drm_vma_node_is_allowed(node, filp)) {
		mutex_unlock(&dev->struct_mutex);
		return -EACCES;
	}

	/* verify mapping size */
	if (vma_pages(vma) > drm_vma_node_size(node)) {
		ret = -EINVAL;
		goto out_unlock;
	}

	gobj = container_of(node, struct drm_gem_object, vma_node);
	obj = to_sdrm_bo(gobj);

	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
	/* FIXME: do we need fb_pgprotect() here? */

	/* This object is _not_ referenced here. Therefore, we _must_ destroy
	 * the mapping before destroying the bo! We do this in
	 * sdrm_gem_free_object(). */

	ret = io_remap_pfn_range(vma, vma->vm_start, obj->fb_base >> PAGE_SHIFT,
				 obj->fb_size, vma->vm_page_prot);

out_unlock:
	mutex_unlock(&dev->struct_mutex);
	return ret;
}
