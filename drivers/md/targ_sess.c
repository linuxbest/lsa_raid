#include "target.h"
#include "raid_if.h"
#include "md.h"

static ssize_t sess_attr_show(struct kobject *kobj,
		struct attribute *attr, char *data);
static ssize_t sess_attr_store(struct kobject *kobj,
		struct attribute *attr, const char *data, size_t len);
static void sess_release(struct kobject *kobj);

struct sess_attribute {
	struct attribute attr;
	ssize_t (*show) (targ_sess_t *sess, char *page);
	ssize_t (*store)(targ_sess_t *sess, char *page, ssize_t count);
};

struct sysfs_ops sess_sysfs_ops = {
	.show = sess_attr_show,
	.store = sess_attr_store,
};

static ssize_t sess_show_devs(targ_sess_t *sess, char *data)
{
	int i;
	ssize_t len = 0;
	for (i = 0; i < sess->dev.nr; i ++) {
		targ_dev_t *dev = sess->dev.array + i;
		len += sprintf(data + len, "%d,%d/%d,%d/%d\n", 
				dev->lun,
				dev->read_count, dev->read_sectors,
				dev->write_count, dev->write_sectors);
	}
	return len;
}

static ssize_t sess_show_cmds(targ_sess_t *sess, char *data)
{
	ssize_t len = 0;
	unsigned long flags;
	targ_req_t *req;
	
	spin_lock_irqsave(&sess->req.lock, flags);
	list_for_each_entry(req, &sess->req.list, list)
		len += targ_req_show(req, data, len);
	spin_unlock_irqrestore(&sess->req.lock, flags);

	return len;
}
static struct sess_attribute sess_cmd_attr = {
	.attr = {.name = "cmds", .mode = S_IRUGO, },
	.show = sess_show_cmds,
};

static struct sess_attribute sess_dev_attr = {
	.attr = {.name = "luns", .mode = S_IRUGO, },
	.show = sess_show_devs,
};

static struct attribute *sess_attrs[] = {
	&sess_dev_attr.attr,
	&sess_cmd_attr.attr,
	NULL,
};

struct kobj_type sess_ktype = {
	.release = sess_release,
	.default_attrs = sess_attrs,
	.sysfs_ops = &sess_sysfs_ops,
};

static ssize_t sess_attr_show(struct kobject *kobj,
		struct attribute *attr, char *data)
{
	struct sess_attribute *sess_attr = 
		container_of(attr, struct sess_attribute, attr);
	int len = 0;
	if (sess_attr->show)
		len = sess_attr->show(container_of(kobj, targ_sess_t, kobj),
				data);
	return len;
}

static ssize_t sess_attr_store(struct kobject *kobj,
		struct attribute *attr, const char *data, size_t len)
{
	struct sess_attribute *sess_attr = 
		container_of(attr, struct sess_attribute, attr);
	if (sess_attr->store)
		len = sess_attr->store(container_of(kobj, targ_sess_t, kobj),
				(char *)data, len);
	return len;
}

static void sess_release(struct kobject *kobj)
{
	targ_sess_t *sess = container_of(kobj, targ_sess_t, kobj);
	targ_group_sess_exit(sess);
	kfree(sess->buf);
	kfree(sess);
}

targ_sess_t *targ_sess_new(const char *wwpn, void *data)
{
	int res = 0;
	targ_port_t *port = targ_port_find_by_data(data);
	targ_sess_t *sess = NULL;

	if (!port) {
		/* TODO */
		goto out;
	}
	sess = targ_port_sess_find(port, wwpn);
	if (sess) {
		sess->data = data;
		goto out;
	}

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess) {
		goto out;
	}

	INIT_LIST_HEAD(&sess->list);
	INIT_LIST_HEAD(&sess->del_sess_list);
	
	spin_lock_init(&sess->req.lock);
	INIT_LIST_HEAD(&sess->req.list);

	sess->kobj.ktype = &sess_ktype;
	sess->kobj.parent = &target.kobj;
	sess->data = data;
	sess->port = port;
	sess->buf  = kmalloc(PAGE_SIZE, GFP_KERNEL);
	strcpy(sess->remote.wwpn, wwpn);

	init_timer(&sess->req.timer);
	sess->req.timer.data = (unsigned long)sess;
	sess->req.timer.function = targ_req_timeout;

	res = kobject_init_and_add(&sess->kobj,
			&sess_ktype,
			&port->kobj,
			sess->remote.wwpn);
	targ_port_sess_add(port, sess);
out:
	return sess;
}

void targ_sess_put(targ_sess_t *sess)
{
	targ_port_sess_remove(sess->port, sess);
}

void targ_sess_set_data(targ_sess_t *sess, void *data)
{
	sess->remote.data = data;
}

void *targ_sess_get_data(targ_sess_t *sess)
{
	return sess->remote.data;
}

int targ_sess_get_dev_nr(targ_sess_t *sess)
{
	return sess->dev.nr;
}

targ_dev_t *targ_sess_get_dev_by_nr(targ_sess_t *sess, int nr)
{
	if (nr > sess->dev.nr)
		return NULL;
	return sess->dev.array + nr;
}

uint64_t targ_dev_get_blocks(targ_dev_t *dev)
{
	return dev->len;
}

EXPORT_SYMBOL(targ_sess_new);
EXPORT_SYMBOL(targ_sess_put);
EXPORT_SYMBOL(targ_sess_set_data);
EXPORT_SYMBOL(targ_sess_get_data);
EXPORT_SYMBOL(targ_sess_get_dev_nr);
EXPORT_SYMBOL(targ_sess_get_dev_by_nr);

EXPORT_SYMBOL(targ_dev_get_blocks);
