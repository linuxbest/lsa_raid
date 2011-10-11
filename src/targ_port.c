#include "raidif.h"
#include "raid_if.h"

static ssize_t port_attr_show(struct kobject *kobj, struct attribute *attr, char *data);
static ssize_t port_attr_store(struct kobject *kobj, struct attribute *attr, const char *data, size_t len);
static void port_release(struct kobject *kobj);

struct port_attribute {
	struct attribute attr;
	ssize_t (*show) (targ_port_t *port, char *page);
	ssize_t (*store)(targ_port_t *port, char *page, ssize_t count);
};

struct sysfs_ops port_sysfs_ops = {
	.show = port_attr_show,
	.store = port_attr_store,
};

static struct attribute *port_attrs[] = {
	NULL,
};

struct kobj_type port_ktype = {
	.release = port_release,
	.default_attrs = port_attrs,
	.sysfs_ops = &port_sysfs_ops,
};

static ssize_t port_attr_show(struct kobject *kobj, struct attribute *attr, char *data)
{
	struct port_attribute *port_attr = 
		container_of(attr, struct port_attribute, attr);
	int len = 0;
	if (port_attr->show)
		len = port_attr->show(container_of(kobj, targ_port_t, kobj), data);
	return len;
}

static ssize_t port_attr_store(struct kobject *kobj, struct attribute *attr, const char *data, size_t len)
{
	struct port_attribute *port_attr = 
		container_of(attr, struct port_attribute, attr);
	if (port_attr->store)
		len = port_attr->store(container_of(kobj, targ_port_t, kobj), (char *)data, len);
	return len;
}

static void port_release(struct kobject *kobj)
{
	targ_port_t *port = container_of(kobj, targ_port_t, kobj);
	kfree(port);
}

targ_port_t *targ_port_new(const char *wwpn, void *data)
{
	int res = 0;
	targ_port_t *port = kzalloc(sizeof(*port), GFP_KERNEL);
	if (!port)
		return NULL;

	INIT_LIST_HEAD(&port->list);
	INIT_LIST_HEAD(&port->sess.list);
	port->kobj.ktype = &port_ktype;
	port->kobj.parent = &raidif.kobj;
	port->data = data;

	res = kobject_init_and_add(&port->kobj,
			&port_ktype,
			&raidif.kobj,
			wwpn);
	list_add_tail(&port->list, &raidif.port.list);

	return port;
}

void targ_port_put(targ_port_t *port)
{
	kobject_put(&port->kobj);
}

targ_port_t *targ_port_find_by_data(void *data)
{
	targ_port_t *port;
	list_for_each_entry(port, &raidif.port.list, list) {
		if (port->data == data)
			return port;
	}
	return NULL;
}

int targ_port_add_sess(targ_port_t *port, targ_sess_t *sess)
{
	list_add_tail(&sess->list, &port->sess.list);
	return 0;
}

EXPORT_SYMBOL(targ_port_new);
EXPORT_SYMBOL(targ_port_put);
