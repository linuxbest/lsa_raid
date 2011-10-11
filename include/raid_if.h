#ifndef _RAID_IF_H_
#define _RAID_IF_H_

typedef struct targ_port targ_port_t;
typedef struct targ_sess targ_sess_t;
typedef struct raid_dev  raid_dev_t;
typedef struct raid_buf  raid_buf_t;
typedef struct scatterlist raid_sg_t;
typedef int (*buf_cb_t)(raid_dev_t *dev, void *priv, int err);

targ_port_t   *targ_port_new             (const char *wwpn, void *port_osdata);
void           targ_port_put             (targ_port_t *port);

targ_sess_t   *targ_sess_new             (const char *wwpn, void *port_osdata);
void           targ_sess_set_data        (targ_sess_t *sess, void *data);
void *         targ_sess_get_data        (targ_sess_t *sess);
void           targ_sess_put             (targ_sess_t *sess);

int            targ_sess_get_dev_nr      (targ_sess_t *sess);
raid_dev_t    *targ_sess_get_dev_by_nr   (targ_sess_t *sess, int nr);
int            raid_dev_put              (raid_dev_t *dev);
uint64_t       raid_dev_get_blocks       (raid_dev_t *dev);
raid_buf_t    *raid_buf_new              (raid_dev_t *dev,
		                          uint64_t blknr,
					  uint16_t blks,
					  int rw,
					  buf_cb_t cb,
					  void *priv);
int           raid_buf_free              (raid_buf_t *buf);
raid_sg_t    *raid_buf_sg                (raid_buf_t *buf, int *count);

#endif
