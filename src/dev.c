#include "raidif.h"

static void    device_release(struct kobject *obj);
static ssize_t device_attr_show(struct kobject *kobj, struct attribute *attr, char *data);
static ssize_t device_attr_store(struct kobject *kobj, struct attribute *attr, const char *data, size_t len);

struct raid_device_attribute {
	struct attribute attr;
	ssize_t (*show)(struct raid_device *dev, char *page);
	ssize_t (*store)(struct raid_device *dev, char *page, ssize_t count);
}; 

static ssize_t device_show_rdev (struct raid_device *dev, char *data);
static ssize_t device_store_rdev(struct raid_device *dev, char *data, ssize_t len);

struct raid_device_attribute device_rdev_attr = {
	.attr = { .name = "rdev", .mode = S_IRUGO | S_IWUGO, },
	.show = device_show_rdev,
	.store = device_store_rdev,
};

static struct attribute *device_attrs[] = {
	&device_rdev_attr.attr,
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

static ssize_t device_attr_show(struct kobject *kobj, struct attribute *attr, char *data)
{
	struct raid_device_attribute *dev_attr = 
		container_of(attr, struct raid_device_attribute, attr);
	ssize_t len = 0;
	if (dev_attr->show)
		len = dev_attr->show(container_of(kobj, struct raid_device, kobj), data);
	return len;
}

static ssize_t device_attr_store(struct kobject *kobj, struct attribute *attr, const char *data, size_t len)
{
	struct raid_device_attribute *dev_attr = 
		container_of(attr, struct raid_device_attribute, attr);
	if (dev_attr->show)
		len = dev_attr->store(container_of(kobj, struct raid_device, kobj), (char *)data, len);
	return len;
}

/* raw device must be block device */
struct rdev {
	struct block_device *bdev;
	struct list_head list;
	int nr;
	uint64_t blocks;
	uint64_t uuid;
};

static struct block_device *
open_bdev_safe(const char *path, void *holder)
{
        struct block_device *bdev;
        struct inode *inode;
        struct nameidata nd;
        int error;

        error = path_lookup(path, LOOKUP_FOLLOW, &nd);
        if (error)
                return ERR_PTR(error);

        inode = nd.path.dentry->d_inode;
        if (!S_ISBLK(inode->i_mode)) {
                return ERR_PTR(-EINVAL);
        }

        bdev = open_by_devnum(inode->i_rdev, FMODE_READ | FMODE_WRITE);

        path_put(&nd.path);

        return bdev;
}

static void 
close_bdev_safe(struct block_device *d)
{
	blkdev_put(d, FMODE_READ | FMODE_WRITE);
}

static ssize_t device_show_rdev(struct raid_device *dev, char *data)
{
	struct rdev *rdev;
	int len = 0;
	char name[BDEVNAME_SIZE];

	len += sprintf(data + len, "##  name        uuid          blocks  \n");
	len += sprintf(data + len, "__  ____  ________________  __________\n");
	list_for_each_entry(rdev, &dev->rdev.list, list) {
		bdevname(rdev->bdev, name);
		len += sprintf(data + len, "%02d, %-4s, %016llx, %lld\n",
				rdev->nr, name, rdev->uuid, rdev->blocks);
	}
	return len;
}

static int device_rdev_add(struct raid_device *dev, const char *path)
{
	struct rdev *rdev; 
	struct block_device *bdev = open_bdev_safe(path, THIS_MODULE);
	int res = 0;

	if (!bdev || IS_ERR(bdev)) {
		res = PTR_ERR(bdev);
		pr_err("raidif:rdev:add: can't open %s, err %d\n", path, res);
		goto out;
	}

	rdev = kzalloc(sizeof(*rdev), GFP_KERNEL);
	if (!rdev) {
		pr_err("raidif:rdev:add: no memmory for rdev %s\n", path);
		close_bdev_safe(bdev);
		res = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&rdev->list);
	rdev->bdev = bdev;
	rdev->blocks = bdev ? bdev->bd_inode->i_size >> 9 : 0;

	list_add_tail(&rdev->list, &dev->rdev.list);
out:
	return res;
}

static ssize_t device_store_rdev(struct raid_device *dev, char *data, ssize_t len)
{
	char *argv[MAX_ARGS];
	int res = 0;

	res = args(data, argv, MAX_ARGS);
	if (res <= 0) 
		goto out;

	if (strcmp(argv[0], "add") == 0)
		device_rdev_add(dev, argv[1]);
out:
	return len;
}

static int raid_rdev_cleanup(struct raid_device *dev)
{
	while (!list_empty(&dev->rdev.list)) {
		struct rdev *rdev = list_entry(dev->rdev.list.next, struct rdev, list);
		list_del_init(&rdev->list);
		close_bdev_safe(rdev->bdev);
		kfree(rdev);
	}

	return 0;
}


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
		pr_err("raidif:device:add: no memory for device %s\n", name);
		res = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&dev->list);
	dev->kobj.ktype  = &device_ktype;
	dev->kobj.parent = &raidif.kobj;
	dev->blocks      = 0;

	INIT_LIST_HEAD(&dev->rdev.list);

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

int device_cleanup(struct raid_device *dev)
{
	raid_rdev_cleanup(dev);
	kobject_put(&dev->kobj);

	return 0;
}

int del_device(const char *name)
{
	struct raid_device *dev;
	int res = -ENOENT;

	list_for_each_entry(dev, &raidif.device.list, list) {
		if (strcmp(dev->kobj.name, name) == 0) {
			list_del_init(&dev->list);
			res = device_cleanup(dev);
			break;
		}
	}

	return res;
}
