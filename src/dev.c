#include "raidif.h"

static void device_release(struct kobject *obj);

struct kobj_type device_ktype = {
	.release = device_release,
	/*.default_attrs = device_attrs,
	.sysfs_ops = &device_sysfs_ops,*/
};

/* device */
int add_device(const char *name)
{
	int res = 0;
	struct raid_device *dev;
	
	list_for_each_entry(dev, &raidif.device.list, list) {
		if (strcmp(dev->kobj.name, name) == 0) {
			res = -EEXIST;
			goto out;
		}
	}

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		printk("no memory for device %s\n", name);
		res = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&dev->list);
	dev->kobj.ktype  = &device_ktype;
	dev->kobj.parent = &raidif.kobj;
	dev->blocks      = 0;

	res = kobject_init_and_add(&dev->kobj,
			&device_ktype,
			&raidif.kobj,
			name);

	list_add_tail(&dev->list, &raidif.device.list);
out:
	return res;
}

static void device_release(struct kobject *obj)
{
	struct raid_device *dev =
		container_of(obj, struct raid_device, kobj);
	kfree(dev);
}

static int device_cleanup(struct raid_device *dev)
{
	list_del_init(&dev->list);
	kobject_put(&dev->kobj);

	return 0;
}

int del_device(const char *name)
{
	struct raid_device *dev;
	int res = -ENOENT;

	list_for_each_entry(dev, &raidif.device.list, list) {
		if (strcmp(dev->kobj.name, name) == 0) {
			res = device_cleanup(dev);
			break;
		}
	}

	return res;
}
