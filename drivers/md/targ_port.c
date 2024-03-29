#include "target.h"
#include "raid_if.h"

static ssize_t port_attr_show(struct kobject *kobj, 
		struct attribute *attr, char *data);
static ssize_t port_attr_store(struct kobject *kobj, 
		struct attribute *attr, const char *data, size_t len);
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

static struct attribute *port_root_attrs[] = {
	NULL,
};

struct kobj_type port_root_ktype = {
	.release = port_release,
	.default_attrs = port_root_attrs,
	.sysfs_ops = &port_sysfs_ops,
};

static ssize_t port_attr_show(struct kobject *kobj, 
		struct attribute *attr, char *data)
{
	struct port_attribute *port_attr = 
		container_of(attr, struct port_attribute, attr);
	int len = 0;
	if (port_attr->show)
		len = port_attr->show(container_of(kobj, targ_port_t, kobj),
				data);
	return len;
}

static ssize_t port_attr_store(struct kobject *kobj, 
		struct attribute *attr, const char *data, size_t len)
{
	struct port_attribute *port_attr = 
		container_of(attr, struct port_attribute, attr);
	if (port_attr->store)
		len = port_attr->store(container_of(kobj, targ_port_t, kobj),
				(char *)data, len);
	return len;
}

static void port_release(struct kobject *kobj)
{
	targ_port_t *port = container_of(kobj, targ_port_t, kobj);
	kfree(port);
}

static void targ_port_del_sess_timer_fn(unsigned long arg)
{
	targ_port_t *port = (targ_port_t *)arg;
	unsigned long flags;

	spin_lock_irqsave(&port->sess.lock, flags);
	while (!list_empty(&port->sess.del_sess_list)) {
		targ_sess_t *sess = list_entry(port->sess.del_sess_list.next,
				typeof(*sess), del_sess_list);
		if (time_after_eq(jiffies, sess->expires)) {
			list_del(&sess->del_sess_list);
			kobject_put(&sess->kobj);
		} else {
			port->sess.sess_del_timer.expires = sess->expires;
			add_timer(&port->sess.sess_del_timer);
		}
	}
	spin_unlock_irqrestore(&port->sess.lock, flags);
}
	
static targ_port_t *port_root;

int targ_port_init(void)
{
	int res = 0;
	targ_port_t *port;

	port_root = port = kzalloc(sizeof(*port), GFP_KERNEL);
	if (!port)
		return -ENOMEM;

	INIT_LIST_HEAD(&port->list);
	port->kobj.ktype = &port_root_ktype;
	port->kobj.parent = &target.kobj;

	spin_lock_init(&port->sess.lock);
	INIT_LIST_HEAD(&port->sess.list);
	strcpy(port->port.wwpn, "ports");

	res = kobject_init_and_add(&port->kobj,
			&port_root_ktype,
			&target.kobj,
			port->port.wwpn);
	return 0;
}

int targ_port_exit(void)
{
	kobject_put(&port_root->kobj);
	return 0;
}

targ_port_t *targ_port_new(const char *wwpn, void *data)
{
	int res = 0;
	targ_port_t *port;
	
	port = kzalloc(sizeof(*port), GFP_KERNEL);
	if (!port)
		return NULL;

	INIT_LIST_HEAD(&port->list);
	port->kobj.ktype = &port_ktype;
	port->kobj.parent = &port_root->kobj;
	port->data = data;

	spin_lock_init(&port->sess.lock);
	INIT_LIST_HEAD(&port->sess.list);
	strcpy(port->port.wwpn, wwpn);

	INIT_LIST_HEAD(&port->sess.del_sess_list);
	init_timer(&port->sess.sess_del_timer);
	port->sess.sess_del_timer.data = (unsigned long)port;
	port->sess.sess_del_timer.function = targ_port_del_sess_timer_fn;

	res = kobject_init_and_add(&port->kobj,
			&port_ktype,
			&port_root->kobj,
			port->port.wwpn);
	list_add_tail(&port->list, &target.port.list);
	pr_info("targ_port(%s): registed.\n", port->port.wwpn);

	return port;
}

void targ_port_put(targ_port_t *port)
{
	unsigned long flags;
	LIST_HEAD(head);

	spin_lock_irqsave(&port->sess.lock, flags);
	while (!list_empty(&port->sess.list)) {
		targ_sess_t *sess = list_entry(port->sess.list.next,
				typeof(*sess), list);
		list_del(&sess->list);
		list_add_tail(&sess->list, &head);
	}
	while (!list_empty(&port->sess.del_sess_list)) {
		targ_sess_t *sess = list_entry(port->sess.del_sess_list.next,
				typeof(*sess), del_sess_list);
		list_del(&sess->del_sess_list);
		list_add_tail(&sess->list, &head);
	}
	del_timer(&port->sess.sess_del_timer);
	spin_unlock_irqrestore(&port->sess.lock, flags);

	while (!list_empty(&head)) {
		targ_sess_t *sess = list_entry(head.next, typeof(*sess), list);
		list_del(&sess->list);
		kobject_put(&sess->kobj);
	}

	pr_info("targ_port(%s): unregisted.\n", port->port.wwpn);
	list_del(&port->list);
	kobject_put(&port->kobj);
}

targ_port_t *targ_port_find_by_data(void *data)
{
	targ_port_t *port;
	list_for_each_entry(port, &target.port.list, list) {
		if (port->data == data)
			return port;
	}
	return NULL;
}

int targ_port_sess_add(targ_port_t *port, targ_sess_t *sess)
{
	list_add_tail(&sess->list, &port->sess.list);
	targ_group_sess_init(sess);
	pr_info("targ_sess(%s:%s) registed.\n",
			port->port.wwpn, sess->remote.wwpn);
	return 0;
}

void targ_port_sess_remove(targ_port_t *port, targ_sess_t *sess)
{
	int dev_loss_tmo = 30 + 5;
	int add_tmr;
	unsigned long flags;

	spin_lock_irqsave(&port->sess.lock, flags);
	if (sess->deleted) 
		goto out;

	add_tmr = list_empty(&port->sess.del_sess_list);
	list_add_tail(&sess->del_sess_list, &port->sess.del_sess_list);
	sess->deleted = 1;

	pr_info("targ_sess(%s:%s) scheduled for deletection in %d secs.\n",
			port->port.wwpn, sess->remote.wwpn, dev_loss_tmo);
	sess->expires = jiffies + dev_loss_tmo * HZ;
	if (add_tmr)
		mod_timer(&port->sess.sess_del_timer, sess->expires);
out:
	spin_unlock_irqrestore(&port->sess.lock, flags);
}

targ_sess_t *targ_port_sess_find(targ_port_t *port, const char *wwpn)
{
	targ_sess_t *sess;
	unsigned long flags;

	spin_lock_irqsave(&port->sess.lock, flags);
	list_for_each_entry(sess, &port->sess.list, list) {
		if (strcmp(sess->remote.wwpn, wwpn) == 0)
			goto found;
	}
	sess = NULL;
found:
	spin_unlock_irqrestore(&port->sess.lock, flags);

	return sess;
}

EXPORT_SYMBOL(targ_port_new);
EXPORT_SYMBOL(targ_port_put);
