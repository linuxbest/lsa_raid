#include "raidif.h"

#define MAX_ARGS  16

struct raidif raidif;

struct raidif_attribute {
	struct attribute attr;
	ssize_t (*show)(char *page);
	ssize_t (*store)(char *page, ssize_t count);
};

static ssize_t raidif_show_devices(char *data);
static ssize_t raidif_store_devices(char *data, ssize_t len);

static struct raidif_attribute raidif_device_attr = {
	.attr = {.name = "devices", .mode = S_IRUGO | S_IWUGO,},
	.show = raidif_show_devices,
	.store = raidif_store_devices,
};

static struct attribute *raidif_attr[] = {
	&raidif_device_attr.attr,
	NULL,
};

static ssize_t raidif_attr_show(struct kobject *kobj, struct attribute *attr, char *data)
{
	struct raidif_attribute *raidif_attr = 
		container_of(attr, struct raidif_attribute, attr);
	ssize_t len = 0;
	if (raidif_attr->show)
		len = raidif_attr->show(data);
	return len;
}

static ssize_t raidif_attr_store(struct kobject *kobj, struct attribute *attr, const char *data, size_t len)
{
	struct raidif_attribute *raidif_attr = 
		container_of(attr, struct raidif_attribute, attr);
	if (raidif_attr->store)
		len = raidif_attr->store((char *)data, len);
	return len;
}

static struct sysfs_ops raidif_sysfs_ops = {
	.show = raidif_attr_show,
	.store= raidif_attr_store,
};

struct kobj_type raidif_ktype = {
	.default_attrs = raidif_attr,
	.sysfs_ops = &raidif_sysfs_ops,
};

/* devices */
static ssize_t raidif_show_devices(char *data)
{
	struct raid_device *dev;
	ssize_t len = 0;

	list_for_each_entry(dev, &raidif.device.list, list) {
		len += sprintf(data + len, "%s %u\n", dev->kobj.name,
				(u32)dev->blocks);
	}

	return len;
}

static int args(char *frame, char *argv[], int argv_max)
{
        int argc = 0;
        char *p = frame;

        while (*p) {
                while (*p && isspace(*p)) {
                        ++p;
                }
                if (*p) {
                        if (argc < argv_max) {
                                argv[argc++] = p;
                        } else {
                                printk("Too many args!\n");
                                return -1;
                        }
                }
                while (*p && !isspace(*p)) {
                        ++p;
                }
                if (*p) {
                        *p++ = '\0';
                }
        }
        return argc;
}

static ssize_t raidif_store_devices(char *data, ssize_t len)
{
	char *argv[MAX_ARGS];
	int argc;

	if ((argc = args(data, argv, MAX_ARGS)) > 0) {
		if (strcmp(argv[0], "add") == 0) {
			if (argc == 2)
				add_device(argv[1]);
		} else if (strcmp(argv[0], "del") == 0) {
			if (argc == 2) 
				del_device(argv[1]);
		} else {
			printk("Illegal command %s\n", argv[0]);
		}
	}

	return len;
}

/* module init & cleanup */
int __init module_new(void)
{
	int res;

	res = kobject_init_and_add(&raidif.kobj, &raidif_ktype, NULL, "raidif");

	return 0;
}

void module_destroy(void)
{
	kobject_put(&raidif.kobj);
}

module_init(module_new);
module_exit(module_destroy);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hu Gang <hugang@soulinfo.com>");
MODULE_DESCRIPTION("RAID Interface API");
