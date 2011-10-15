#include "target.h"
#include "raid_if.h"

static ssize_t sess_attr_show(struct kobject *kobj,
		struct attribute *attr, char *data);
static ssize_t sess_attr_store(struct kobject *kobj,
		struct attribute *attr, const char *data, size_t len);
static void sess_release(struct kobject *kobj);
static void targ_sess_dev_assign(targ_sess_t *sess);

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
		len += sprintf(data + len, "%d %p\n", dev->lun, dev->dev);
	}
	return len;
}

static struct sess_attribute sess_dev_attr = {
	.attr = {.name = "luns", .mode = S_IRUGO, },
	.show = sess_show_devs,
};

static struct attribute *sess_attrs[] = {
	&sess_dev_attr.attr,
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
	sess->kobj.ktype = &sess_ktype;
	sess->kobj.parent = &target.kobj;
	sess->data = data;
	sess->port = port;
	strcpy(sess->remote.wwpn, wwpn);

	res = kobject_init_and_add(&sess->kobj,
			&sess_ktype,
			&port->kobj,
			sess->remote.wwpn);
	targ_port_sess_add(port, sess);
	targ_sess_dev_assign(sess);
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

/* assign the device to session */
static void targ_sess_dev_assign(targ_sess_t *sess)
{
	int nr = 0, i = 0;
	struct raid_device *rdev;
	struct targ_dev *mem = NULL;

	list_for_each_entry(rdev, &target.device.list, list) {
		nr ++;
	}

	mem = kzalloc(sizeof(struct targ_dev)*nr, GFP_ATOMIC);
	if (mem == NULL) {
		pr_info("targ_sess: assign device memory failed, %d\n", nr);
		return;
	}

	list_for_each_entry(rdev, &target.device.list, list) {
		targ_dev_t *dev = &mem[i];
		char buf[32];
		sprintf(buf, "lun-%d\n", i);
		dev->dev = rdev;
		dev->lun = i;
		dev->sess = sess;
		i ++;
	}

	sess->dev.array = mem;
	sess->dev.nr = i;
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
	return dev->dev->blocks;
}

struct targ_buf {
};

typedef struct target_req {
	struct list_head list;
	struct targ_buf buf;
	targ_dev_t *dev;
	uint64_t sector;
	uint16_t num;
	int rw;
	buf_cb_t cb;
	void *priv;
} targ_req_t;

static struct kmem_cache *req_cache;

int __init req_cache_init(void)
{
	req_cache = kmem_cache_create("targ_req", sizeof(targ_req_t), 
			0, 0, NULL);
	if (!req_cache)
		return -ENOMEM;
	return 0;
}

void req_cache_exit(void)
{
	kmem_cache_destroy(req_cache);
}

targ_buf_t *targ_buf_new(targ_dev_t *dev, uint64_t blknr, 
		uint16_t blks, int rw, buf_cb_t cb, void *priv)
{
	targ_req_t *req = kmem_cache_zalloc(req_cache, GFP_ATOMIC);
	req->dev   = dev;
	req->sector= blknr;
	req->num   = blks;
	req->rw    = rw;
	req->cb    = cb;
	req->priv  = priv;
	return &req->buf;
}

int targ_buf_free(targ_buf_t *buf)
{
	targ_req_t *req = container_of(buf, targ_req_t, buf);
	kmem_cache_free(req_cache, req);
	return 0;
}

targ_sg_t *targ_buf_sg(targ_buf_t *buf, int *count)
{
	return NULL;
}

EXPORT_SYMBOL(targ_sess_new);
EXPORT_SYMBOL(targ_sess_put);
EXPORT_SYMBOL(targ_sess_set_data);
EXPORT_SYMBOL(targ_sess_get_data);
EXPORT_SYMBOL(targ_sess_get_dev_nr);
EXPORT_SYMBOL(targ_sess_get_dev_by_nr);

EXPORT_SYMBOL(targ_dev_get_blocks);
EXPORT_SYMBOL(targ_buf_sg);
EXPORT_SYMBOL(targ_buf_free);
EXPORT_SYMBOL(targ_buf_new);
