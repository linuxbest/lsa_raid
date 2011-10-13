#include "raidif.h"

static struct kobj_type raidif_ktype;

struct raidif raidif = {
	.kobj = {
		.name = NULL,
		.ktype = &raidif_ktype,
	},
	.device = {
		.lock = SPIN_LOCK_UNLOCKED,
		.list = LIST_HEAD_INIT(raidif.device.list),
	},
	.port = {
		.lock = SPIN_LOCK_UNLOCKED,
		.list = LIST_HEAD_INIT(raidif.port.list),
	},
};

struct raidif_attribute {
	struct attribute attr;
	ssize_t (*show)(char *page);
	ssize_t (*store)(char *page, ssize_t count);
};

static ssize_t raidif_show_devices(char *data);
static ssize_t raidif_store_devices(char *data, ssize_t len);

static ssize_t raidif_show_ports(char *data);
static ssize_t raidif_store_ports(char *data, ssize_t len);

static struct raidif_attribute raidif_device_attr = {
	.attr = {.name = "devices", .mode = S_IRUGO | S_IWUGO,},
	.show = raidif_show_devices,
	.store = raidif_store_devices,
};

static struct raidif_attribute raidif_port_attr = {
	.attr = {.name = "ports", .mode = S_IRUGO | S_IWUGO,},
	.show = raidif_show_ports,
	.store = raidif_store_ports,
};

static struct attribute *raidif_attr[] = {
	&raidif_device_attr.attr,
	&raidif_port_attr.attr,
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

static struct kobj_type raidif_ktype = {
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

int args(char *frame, char *argv[], int argv_max)
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
	return len;
}

static ssize_t raidif_show_ports(char *data)
{
	struct targ_port *port;
	ssize_t len = 0;

	list_for_each_entry(port, &raidif.port.list, list) {
		len += sprintf(data + len, "%s 0x%x\n", port->kobj.name,
				(u32)port->data);
	}

	return len;
}

static ssize_t raidif_store_ports(char *data, ssize_t len)
{
	return len;
}

/* module init & cleanup */
int __init module_new(void)
{
	int res;

	dm_linear_init();
	res = kobject_init_and_add(&raidif.kobj, &raidif_ktype, NULL, "raidif");

	return 0;
}

void module_destroy(void)
{
	while (!list_empty(&raidif.device.list)) {
		struct raid_device *dev = list_entry(raidif.device.list.next, struct raid_device, list);
		list_del_init(&dev->list);
		/* TODO clean the device */
	}
	kobject_put(&raidif.kobj);
	dm_linear_exit();
}

module_init(module_new);
module_exit(module_destroy);

MODULE_VERSION(GITVERSION);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hu Gang <hugang@soulinfo.com>");
MODULE_DESCRIPTION("RAID Interface API");
