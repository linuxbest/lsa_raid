#ifndef _RAID_IF_H_
#define _RAID_IF_H_

typedef struct targ_port targ_port_t;
typedef struct targ_sess targ_sess_t;
typedef struct targ_dev  targ_dev_t;
typedef struct targ_buf  targ_buf_t;
typedef struct scatterlist targ_sg_t;
typedef int (*buf_cb_t)(targ_dev_t *dev, targ_buf_t *buf, void *priv, int err);

targ_port_t   *targ_port_new             (const char *wwpn, void *port_osdata);
void           targ_port_put             (targ_port_t *port);

targ_sess_t   *targ_sess_new             (const char *wwpn, void *port_osdata);
void           targ_sess_set_data        (targ_sess_t *sess, void *data);
void *         targ_sess_get_data        (targ_sess_t *sess);
void           targ_sess_put             (targ_sess_t *sess);

int            targ_sess_get_dev_nr      (targ_sess_t *sess);
targ_dev_t    *targ_sess_get_dev_by_nr   (targ_sess_t *sess, int nr);
int            targ_dev_put              (targ_dev_t *dev);
uint64_t       targ_dev_get_blocks       (targ_dev_t *dev);
targ_buf_t    *targ_buf_new              (targ_dev_t *dev,
		                          uint64_t blknr,
					  uint16_t blks,
					  int rw,
					  buf_cb_t cb,
					  void *priv);
int           targ_buf_free              (targ_buf_t *buf);
targ_sg_t    *targ_buf_map               (targ_buf_t *buf, 
		                          struct device *dev, 
					  int dir,
					  int *sg_cnt);
void          targ_buf_unmap             (targ_buf_t *buf, 
		                          struct device *dev, 
					  int dir);

#endif
