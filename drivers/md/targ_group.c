#include <linux/namei.h>
#include <linux/fs.h>

#include "target.h"
#include "raid_if.h"

static ssize_t group_attr_show(struct kobject *kobj, 
		struct attribute *attr, char *data);
static ssize_t group_attr_store(struct kobject *kobj, 
		struct attribute *attr, const char *data, size_t len);
static void group_release(struct kobject *kobj);

typedef enum {
	PORT   = 0,
	WWPN   = 1,
	DEVICE = 2,
} attr_type_t;

struct attr_list {
	struct list_head list;
	char data[128];

	union {
		struct {
			struct block_device *bdev;
			struct dm_table *table;
			struct mddev_s *mddev;
			sector_t sector;
		} device;
	};
};

struct group_attribute {
	struct attribute attr;
	ssize_t (*show) (targ_group_t *group,
			struct group_attribute *attr, char *page);
	ssize_t (*store)(targ_group_t *group,
			struct group_attribute *attr, char *page, 
			ssize_t count);
	ssize_t (*attr_init)(struct attr_list *al);
	ssize_t (*attr_exit)(struct attr_list *al);
	ssize_t (*attr_show)(struct attr_list *al, char *page, ssize_t len);
	attr_type_t type;
};

static struct attr_list *group_attr_find(struct list_head *head, const char *name)
{
	struct attr_list *al;
	list_for_each_entry(al, head, list) {
		if (strcmp(al->data, name) == 0)
			return al;
	}
	return NULL;
}

static void group_attr_clean(struct list_head *head,
		struct group_attribute *attr)
{
	while (!list_empty(head)) {
		struct attr_list *al = list_entry(head->next, 
				struct attr_list, list);
		debug("clean %s\n", al->data);
		list_del(&al->list);
		if (attr->attr_exit)
			attr->attr_exit(al);
		kfree(al);
	}
}
static ssize_t group_show_attr(targ_group_t *group, 
		struct group_attribute *attr, char *page)
{
	ssize_t len = 0;
	struct attr_list *al;
	int i = 0;

	list_for_each_entry(al, &group->head[attr->type], list) {
		len += sprintf(page+len, "%d,%s", i, al->data);
		if (attr->attr_show)
			len += attr->attr_show(al, page, len);
		len += sprintf(page+len, "\n");
		i ++;
	}

	return len;
}

static ssize_t group_store_attr(targ_group_t *group,
		struct group_attribute *attr, char *page, ssize_t count)
{
#define MAXWORDS 9
	char *words[MAXWORDS];
	char tmpbuf[256];
	int nwords, i = 0, len = count;

	ssize_t res = count;
	struct attr_list *al;

	struct list_head *head;

	if (len > sizeof(tmpbuf)-1)
		return -E2BIG;
	memcpy(tmpbuf, page, len);
	tmpbuf[len] = '\0';

	nwords = tokenize(tmpbuf, words, MAXWORDS);
	if (nwords < 0)
		return -EINVAL;
	
	head = &group->head[attr->type];

	for (i = 0; i < nwords ; i ++) {
		const char *name = words[i];
		debug("%d, %s, %d\n", i, name, attr->type);
		if (strcmp(name, "clean") == 0) {
			group_attr_clean(head, attr);
			continue;
		}

		if (group_attr_find(head, name)) {
			res = -EEXIST;
			break;
		}

		al = kzalloc(sizeof(*al), GFP_KERNEL);
		if (al == NULL) {
			res = -ENOMEM;
			break;
		}	
		strcpy(al->data, name);
		list_add_tail(&al->list, head);
		if (attr->attr_init)
			attr->attr_init(al);
	}

	return res;
}

static struct block_device * open_bdev_safe(const char *pathname, int f, void *holder)
{
        struct block_device *bdev;
        struct inode *inode;
	struct path path;
	int error;

	error = kern_path(pathname, LOOKUP_FOLLOW, &path);
	if (error)
		return ERR_PTR(-EINVAL);

	inode = path.dentry->d_inode;
	if (!S_ISBLK(inode->i_mode)) {
		path_put(&path);
		return ERR_PTR(-EINVAL);
        }

	bdev = blkdev_get_by_dev(inode->i_rdev, FMODE_READ|FMODE_WRITE, holder);
	path_put(&path);

        return bdev;
}

static void close_bdev_safe(struct block_device *d)
{
	blkdev_put(d, FMODE_READ | FMODE_WRITE);
}

ssize_t group_device_init(struct attr_list *al)
{
	struct block_device *bdev;
	bdev = open_bdev_safe(al->data, 0, THIS_MODULE);
	if (IS_ERR(bdev))
		return -ENODEV;
	al->device.bdev = bdev;
	al->device.sector = i_size_read(bdev->bd_inode) >> 9;
	return 0;
}

ssize_t group_device_show(struct attr_list *al, char *page, ssize_t len)
{
	char b[BDEVNAME_SIZE];

	if (al->device.bdev == NULL) 
		return len;

	len += sprintf(page+len, ",%s,%lld", bdevname(al->device.bdev, b),
			al->device.sector);
	return len;
}

struct sysfs_ops group_sysfs_ops = {
	.show = group_attr_show,
	.store = group_attr_store,
};

static struct group_attribute group_attribute_port = {
	.attr = {.name = "port", .mode = S_IRUGO | S_IWUGO, },
	.show = group_show_attr,
	.store = group_store_attr,
	.type = PORT,
};

static struct group_attribute group_attribute_wwpn= {
	.attr = {.name = "wwpn", .mode = S_IRUGO | S_IWUGO, },
	.show = group_show_attr,
	.store = group_store_attr,
	.type = WWPN,
};

static struct group_attribute group_attribute_device = {
	.attr = {.name = "device", .mode = S_IRUGO | S_IWUGO, },
	.show = group_show_attr,
	.store = group_store_attr,
	.attr_init = group_device_init,
	.attr_show = group_device_show,
	.type = DEVICE,
};

static struct attribute *group_attrs[] = {
	&group_attribute_port.attr,
	&group_attribute_wwpn.attr,
	&group_attribute_device.attr,
	NULL,
};

static struct attribute *root_group_attrs[] = {
	NULL,
};

struct kobj_type group_ktype = {
	.release = group_release,
	.default_attrs = group_attrs,
	.sysfs_ops = &group_sysfs_ops,
};

struct kobj_type root_group_ktype = {
	.release = group_release,
	.default_attrs = root_group_attrs,
	.sysfs_ops = &group_sysfs_ops,
};

static ssize_t group_attr_show(struct kobject *kobj, 
		struct attribute *attr, char *data)
{
	struct group_attribute *group_attr = 
		container_of(attr, struct group_attribute, attr);
	int len = 0;
	if (group_attr->show)
		len = group_attr->show(container_of(kobj, targ_group_t, kobj),
				group_attr, data);
	return len;
}

static ssize_t group_attr_store(struct kobject *kobj, 
		struct attribute *attr, const char *data, size_t len)
{
	struct group_attribute *group_attr = 
		container_of(attr, struct group_attribute, attr);
	if (group_attr->store)
		len = group_attr->store(container_of(kobj, targ_group_t, kobj),
				group_attr, (char *)data, len);
	return len;
}

static void group_release(struct kobject *kobj)
{
	targ_group_t *group = container_of(kobj, targ_group_t, kobj);
	group_attr_clean(&group->head[PORT], &group_attribute_port);
	group_attr_clean(&group->head[WWPN], &group_attribute_wwpn);
	group_attr_clean(&group->head[DEVICE], &group_attribute_device);
	kfree(group);
}

static targ_group_t *root_group = NULL;

static targ_group_t *targ_group_new(char *name)
{
	int res = 0;
	targ_group_t *group;
	
	group = kzalloc(sizeof(*group), GFP_KERNEL);
	if (!group)
		return NULL;

	INIT_LIST_HEAD(&group->list);
	group->kobj.ktype = &group_ktype;
	group->kobj.parent = &root_group->kobj;

	INIT_LIST_HEAD(&group->head[0]);
	INIT_LIST_HEAD(&group->head[1]);
	INIT_LIST_HEAD(&group->head[2]);

	res = kobject_init_and_add(&group->kobj,
			&group_ktype,
			&root_group->kobj,
			name);
	list_add_tail(&group->list, &target.group.list);
	debug("targ_group(%s): registed.\n", group->kobj.name);

	return group;
}

static void targ_group_put(targ_group_t *group)
{
	debug("targ_group(%s): unregisted.\n", group->kobj.name);
	list_del(&group->list);
	kobject_put(&group->kobj);
}

static targ_group_t *default_group = NULL;

int targ_group_init(void)
{
	int res = 0;
	targ_group_t *group;
	
	root_group = group = kzalloc(sizeof(*group), GFP_KERNEL);
	if (!group)
		return -ENOMEM;

	INIT_LIST_HEAD(&group->list);
	group->kobj.ktype = &root_group_ktype;
	group->kobj.parent = &target.kobj;
	
	INIT_LIST_HEAD(&group->head[0]);
	INIT_LIST_HEAD(&group->head[1]);
	INIT_LIST_HEAD(&group->head[2]);

	res = kobject_init_and_add(&group->kobj,
			&root_group_ktype,
			&target.kobj,
			"groups");
	
	default_group = targ_group_new("Default");

	return default_group == NULL;
}

int targ_group_exit(void)
{
	while (!list_empty(&target.group.list)) {
		targ_group_t *group = list_entry(target.group.list.next, 
				targ_group_t, list);
		targ_group_put(group);
	}
	kobject_put(&root_group->kobj);

	return 0;
}

int targ_group_sess_init(struct targ_sess *sess)
{
	return 0;
}
