#include "target.h"
#include "raid_if.h"

static ssize_t group_attr_show(struct kobject *kobj, 
		struct attribute *attr, char *data);
static ssize_t group_attr_store(struct kobject *kobj, 
		struct attribute *attr, const char *data, size_t len);
static void group_release(struct kobject *kobj);

struct group_attribute {
	struct attribute attr;
	ssize_t (*show) (targ_group_t *group, char *page);
	ssize_t (*store)(targ_group_t *group, char *page, ssize_t count);
};

struct sysfs_ops group_sysfs_ops = {
	.show = group_attr_show,
	.store = group_attr_store,
};

static struct attribute *group_attrs[] = {
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
				data);
	return len;
}

static ssize_t group_attr_store(struct kobject *kobj, 
		struct attribute *attr, const char *data, size_t len)
{
	struct group_attribute *group_attr = 
		container_of(attr, struct group_attribute, attr);
	if (group_attr->store)
		len = group_attr->store(container_of(kobj, targ_group_t, kobj),
				(char *)data, len);
	return len;
}

static void group_release(struct kobject *kobj)
{
	targ_group_t *group = container_of(kobj, targ_group_t, kobj);
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

	INIT_LIST_HEAD(&group->port.list);
	INIT_LIST_HEAD(&group->wwpn.list);
	INIT_LIST_HEAD(&group->device.list);

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

	INIT_LIST_HEAD(&group->port.list);
	INIT_LIST_HEAD(&group->wwpn.list);
	INIT_LIST_HEAD(&group->device.list);

	res = kobject_init_and_add(&group->kobj,
			&group_ktype,
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
