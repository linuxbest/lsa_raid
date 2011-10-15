/*
 * Copyright (C) 2001-2003 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#include "dm.h"
#include <linux/module.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/device-mapper.h>

#include "target.h"

#define DM_MSG_PREFIX "linear"

static int lv_add(struct raid_device *rd, const char *name, sector_t len);
static int lv_del(struct raid_device *rd);

/*
 * Construct a linear mapping: <dev_path> <offset>
 */
static int linear_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct raid_device *rd;
	struct linear_c *lc;
	unsigned long long tmp;

	if (argc != 2) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	rd = kzalloc(sizeof(*rd), GFP_KERNEL);
	if (rd == NULL) {
		ti->error = "dm-linear: Cannot allocate linear context";
		return -ENOMEM;
	}
	lc = &rd->lc;

	if (sscanf(argv[1], "%llu", &tmp) != 1) {
		ti->error = "dm-linear: Invalid device sector";
		goto bad;
	}
	lc->start = tmp;

	if (dm_get_device(ti, argv[0], lc->start, ti->len,
			  dm_table_get_mode(ti->table), &lc->dev)) {
		ti->error = "dm-linear: Device lookup failed";
		goto bad;
	}

	ti->num_flush_requests = 1;
	ti->private = lc;

	lv_add(rd, NULL, ti->len);

	return 0;

      bad:
	kfree(rd);
	return -EINVAL;
}

static void linear_dtr(struct dm_target *ti)
{
	struct linear_c *lc = (struct linear_c *) ti->private;
	struct raid_device *rd = container_of(lc, struct raid_device, lc);

	dm_put_device(ti, lc->dev);
	lv_del(rd);
}

static sector_t linear_map_sector(struct dm_target *ti, sector_t bi_sector)
{
	struct linear_c *lc = ti->private;

	return lc->start + (bi_sector - ti->begin);
}

static void linear_map_bio(struct dm_target *ti, struct bio *bio)
{
	struct linear_c *lc = ti->private;

	bio->bi_bdev = lc->dev->bdev;
	if (bio_sectors(bio))
		bio->bi_sector = linear_map_sector(ti, bio->bi_sector);
}

static int linear_map(struct dm_target *ti, struct bio *bio,
		      union map_info *map_context)
{
	linear_map_bio(ti, bio);

	return DM_MAPIO_REMAPPED;
}

static int linear_status(struct dm_target *ti, status_type_t type,
			 char *result, unsigned int maxlen)
{
	struct linear_c *lc = (struct linear_c *) ti->private;

	switch (type) {
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;

	case STATUSTYPE_TABLE:
		snprintf(result, maxlen, "%s %llu", lc->dev->name,
				(unsigned long long)lc->start);
		break;
	}
	return 0;
}

static int linear_ioctl(struct dm_target *ti, unsigned int cmd,
			unsigned long arg)
{
	struct linear_c *lc = (struct linear_c *) ti->private;
	return __blkdev_driver_ioctl(lc->dev->bdev, lc->dev->mode, cmd, arg);
}

static int linear_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
			struct bio_vec *biovec, int max_size)
{
	struct linear_c *lc = ti->private;
	struct request_queue *q = bdev_get_queue(lc->dev->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = lc->dev->bdev;
	bvm->bi_sector = linear_map_sector(ti, bvm->bi_sector);

	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static int linear_iterate_devices(struct dm_target *ti,
				  iterate_devices_callout_fn fn, void *data)
{
	struct linear_c *lc = ti->private;

	return fn(ti, lc->dev, lc->start, ti->len, data);
}

static struct target_type linear_target = {
	.name   = "linear",
	.version = {1, 1, 0},
	.module = THIS_MODULE,
	.ctr    = linear_ctr,
	.dtr    = linear_dtr,
	.map    = linear_map,
	.status = linear_status,
	.ioctl  = linear_ioctl,
	.merge  = linear_merge,
	.iterate_devices = linear_iterate_devices,
};

static void    device_release(struct kobject *obj);
static ssize_t device_attr_show(struct kobject *kobj,
		struct attribute *attr, char *data);
static ssize_t device_attr_store(struct kobject *kobj,
		struct attribute *attr, const char *data, size_t len);

struct raid_device_attribute {
	struct attribute attr;
	ssize_t (*show)(struct raid_device *dev, char *page);
	ssize_t (*store)(struct raid_device *dev, char *page, ssize_t count);
}; 

static ssize_t device_show_uuid (struct raid_device *dev, 
		char *data);
static ssize_t device_store_uuid (struct raid_device *dev, 
		char *data, ssize_t len);

struct raid_device_attribute device_uuid_attr = {
	.attr = { .name = "uuid", .mode = S_IRUGO | S_IWUGO, },
	.show = device_show_uuid,
	.store = device_store_uuid,
};

static struct attribute *device_attrs[] = {
	&device_uuid_attr.attr,
	NULL,
};

struct sysfs_ops device_sysfs_ops = {
	.show = device_attr_show,
	.store = device_attr_store,
};

struct kobj_type device_ktype = {
	.release = device_release,
	.default_attrs = device_attrs,
	.sysfs_ops = &device_sysfs_ops,
};

static ssize_t device_attr_show(struct kobject *kobj, 
		struct attribute *attr, char *data)
{
	struct raid_device_attribute *dev_attr = 
		container_of(attr, struct raid_device_attribute, attr);
	ssize_t len = 0;
	if (dev_attr->show)
		len = dev_attr->show(container_of(kobj, struct raid_device, kobj), data);
	return len;
}

static ssize_t device_attr_store(struct kobject *kobj,
		struct attribute *attr, const char *data, size_t len)
{
	struct raid_device_attribute *dev_attr = 
		container_of(attr, struct raid_device_attribute, attr);
	if (dev_attr->show)
		len = dev_attr->store(container_of(kobj, struct raid_device, kobj), 
				(char *)data, len);
	return len;
}

static ssize_t device_show_uuid(struct raid_device *dev, char *data)
{
	return 0;
}

static ssize_t device_store_uuid(struct raid_device *dev, char *data,
		ssize_t len)
{
	return len;
}

/* device */
static int lv_add(struct raid_device *dev, const char *name, sector_t len)
{
	int res = 0;
	char buf[32];

	sprintf(buf, "dm-%p", dev);

	INIT_LIST_HEAD(&dev->list);
	dev->kobj.ktype  = &device_ktype;
	dev->kobj.parent = &target.kobj;
	dev->blocks      = len;

	res = kobject_init_and_add(&dev->kobj,
			&device_ktype,
			&target.kobj,
			buf);

	list_add_tail(&dev->list, &target.device.list);

	return res;
}

static void device_release(struct kobject *obj)
{
	struct raid_device *dev =
		container_of(obj, struct raid_device, kobj);
	kfree(dev);
}

int device_cleanup(struct raid_device *dev)
{
	kobject_put(&dev->kobj);

	return 0;
}

static int lv_del(struct raid_device *dev)
{
	list_del_init(&dev->list);
	device_cleanup(dev);
	return 0;
}

int __init dm_linear_init(void)
{
	int r = dm_register_target(&linear_target);

	if (r < 0)
		DMERR("register failed %d", r);

	return r;
}

void dm_linear_exit(void)
{
	dm_unregister_target(&linear_target);
}
