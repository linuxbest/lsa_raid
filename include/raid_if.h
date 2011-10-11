#ifndef _RAID_IF_H_
#define _RAID_IF_H_

typedef struct raid_bus raid_bus_t;
typedef struct raid_dev raid_dev_t;
typedef struct raid_buf raid_buf_t;
typedef struct scatterlist raid_sg_t;
typedef int (*buf_cb_t)(raid_dev_t *dev, void *priv, int err);

raid_bus_t *raid_bus_new             (const char *name);
void        raid_bus_put             (raid_bus_t *bus);
int         raid_bus_set_portal_data (raid_bus_t *bus, void *data);
void *      raid_bus_get_portal_data (raid_bus_t *bus);
int         raid_bus_set_local_wwpn  (raid_bus_t *bus, const char *wwpn);
int         raid_bus_set_remote_wwpn (raid_bus_t *bus, const char *wwpn);
int         raid_bus_get_dev_nr      (raid_bus_t *bus);
raid_dev_t *raid_bus_get_dev_by_nr   (raid_bus_t *bus, int nr);
int         raid_dev_put             (raid_dev_t *dev, raid_bus_t *bus);
uint64_t    raid_dev_get_blocks      (raid_dev_t *dev);
raid_buf_t *raid_buf_new             (raid_dev_t *dev,
		                      uint64_t blknr,
				      uint16_t blks,
				      int rw,
				      buf_cb_t cb,
				      void *priv);
int         raid_buf_free            (raid_buf_t *buf);
raid_sg_t  *raid_buf_sg              (raid_buf_t *buf, int *count);

#endif
