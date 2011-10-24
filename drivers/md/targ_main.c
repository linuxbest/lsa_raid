#include "target.h"

static struct kobj_type target_ktype;

struct target target = {
	.kobj = {
		.name = NULL,
		.ktype = &target_ktype,
	},
	.device = {
		.list = LIST_HEAD_INIT(target.device.list),
	},
	.port = {
		.list = LIST_HEAD_INIT(target.port.list),
	},
	.group = {
		.list = LIST_HEAD_INIT(target.group.list),
	},
};

struct target_attribute {
	struct attribute attr;
	ssize_t (*show)(char *page);
	ssize_t (*store)(char *page, ssize_t count);
};

static ssize_t target_show_devices(char *data);
static ssize_t target_store_devices(char *data, ssize_t len);

static ssize_t target_show_ports(char *data);
static ssize_t target_store_ports(char *data, ssize_t len);

static struct target_attribute target_device_attr = {
	.attr = {.name = "devices", .mode = S_IRUGO | S_IWUGO,},
	.show = target_show_devices,
	.store = target_store_devices,
};

static struct target_attribute target_port_attr = {
	.attr = {.name = "ports", .mode = S_IRUGO | S_IWUGO,},
	.show = target_show_ports,
	.store = target_store_ports,
};

static struct attribute *target_attr[] = {
	&target_device_attr.attr,
	&target_port_attr.attr,
	NULL,
};

static ssize_t target_attr_show(struct kobject *kobj, 
		struct attribute *attr, char *data)
{
	struct target_attribute *target_attr = 
		container_of(attr, struct target_attribute, attr);
	ssize_t len = 0;
	if (target_attr->show)
		len = target_attr->show(data);
	return len;
}

static ssize_t target_attr_store(struct kobject *kobj,
		struct attribute *attr, const char *data, size_t len)
{
	struct target_attribute *target_attr = 
		container_of(attr, struct target_attribute, attr);
	if (target_attr->store)
		len = target_attr->store((char *)data, len);
	return len;
}

static struct sysfs_ops target_sysfs_ops = {
	.show = target_attr_show,
	.store= target_attr_store,
};

static struct kobj_type target_ktype = {
	.default_attrs = target_attr,
	.sysfs_ops = &target_sysfs_ops,
};

/* devices */
static ssize_t target_show_devices(char *data)
{
	struct raid_device *dev;
	ssize_t len = 0;

	list_for_each_entry(dev, &target.device.list, list) {
		len += sprintf(data + len, "%s\n", dev->kobj.name);
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

/*
 * Split the buffer `buf' into space-separated words.
 * Handles simple " and ' quoting, i.e. without nested,
 * embedded or escaped \".  Return the number of words
 * or <0 on error.
 */
int tokenize(char *buf, char *words[], int maxwords)
{
	int nwords = 0;

	while (*buf) {
		char *end;

		/* Skip leading whitespace */
		buf = skip_spaces(buf);
		if (!*buf)
			break;	/* oh, it was trailing whitespace */

		/* Run `end' over a word, either whitespace separated or quoted */
		if (*buf == '"' || *buf == '\'') {
			int quote = *buf++;
			for (end = buf ; *end && *end != quote ; end++)
				;
			if (!*end)
				return -EINVAL;	/* unclosed quote */
		} else {
			for (end = buf ; *end && !isspace(*end) ; end++)
				;
			BUG_ON(end == buf);
		}
		/* Here `buf' is the start of the word, `end' is one past the end */

		if (nwords == maxwords)
			return -EINVAL;	/* ran out of words[] before bytes */
		if (*end)
			*end++ = '\0';	/* terminate the word */
		words[nwords++] = buf;
		buf = end;
	}

	if (0) {
		int i;
		printk(KERN_INFO "%s: split into words:", __func__);
		for (i = 0 ; i < nwords ; i++)
			printk(" \"%s\"", words[i]);
		printk("\n");
	}

	return nwords;
}

static ssize_t target_store_devices(char *data, ssize_t len)
{
	return len;
}

static ssize_t target_show_ports(char *data)
{
	struct targ_port *port;
	ssize_t len = 0;

	list_for_each_entry(port, &target.port.list, list) {
		len += sprintf(data + len, "%s 0x%x\n", port->kobj.name,
				(u32)port->data);
	}

	return len;
}

static ssize_t target_store_ports(char *data, ssize_t len)
{
	return len;
}

/* module init & cleanup */
int dm_targ_init(void)
{
	int res;

	spin_lock_init(&target.device.lock);
	spin_lock_init(&target.port.lock);
	spin_lock_init(&target.group.lock);

	req_cache_init();
	res = kobject_init_and_add(&target.kobj, 
			&target_ktype, NULL, "target");
	targ_group_init();

	return 0;
}

void dm_targ_exit(void)
{
	while (!list_empty(&target.device.list)) {
		struct raid_device *dev = list_entry(target.device.list.next,
				struct raid_device, list);
		list_del_init(&dev->list);
		/* TODO clean the device */
	}
	targ_group_exit();
	kobject_put(&target.kobj);
	req_cache_exit();
}

module_init(dm_targ_init);
module_exit(dm_targ_exit);

MODULE_VERSION(GITVERSION);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hu Gang <hugang@soulinfo.com>");
MODULE_DESCRIPTION("Target");
