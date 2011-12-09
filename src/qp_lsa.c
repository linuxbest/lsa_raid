#include "qp_port.h"
#include "qp_lsa.h"
#include "bsp.h"
#include "md_raid5.h"

static QEvent const *l_cacheQueueSto[64];
static QEvent const *l_raid5QueueSto[64];
static QSubscrList l_subscrSto[MAX_PUB_SIG];

union SmallEvents {
	void   *e0;
	uint8_t e1[sizeof(QEvent)];
};

union MediumEvents {
	void   *e0;
	uint8_t e1[sizeof(CacheRWEvt)];
};

static struct event_pool {
	void *sto;
	int pool_size;
	int event_size;
} EventPool[2] = {
	[0] = {
		.pool_size = 1024,
		.event_size = sizeof(union SmallEvents),
	},
	[1] = {
		.pool_size = 1024,
		.event_size = sizeof(union MediumEvents),
	},
};

int lsa_raid_init(void)
{
	int i;
	
	Cache_ctor();
	Raid5_ctor();
	
	BSP_init(0, NULL);
	
	QF_init();
	
	for (i = 0; i < Q_DIM(EventPool); i++) {
		struct event_pool *ep = &EventPool[i];
		int tlen = ep->pool_size * ep->event_size;
		ep->sto = kmalloc(tlen, GFP_KERNEL);
		QF_poolInit(ep->sto, tlen, ep->event_size);
	}
	QF_psInit(l_subscrSto, Q_DIM(l_subscrSto));   /* init publish-subscribe */

	QS_OBJ_DICTIONARY(&EventPool[0]);
	QS_OBJ_DICTIONARY(&EventPool[1]);

	QS_SIG_DICTIONARY(TERMINATE_SIG,        0);
	QS_SIG_DICTIONARY(CACHE_RW_REQUEST_SIG, 0);
	QS_SIG_DICTIONARY(CACHE_RW_REPLY_SIG,   0);
	
	QActive_start(AO_cache,
		      1,
		      l_cacheQueueSto, Q_DIM(l_cacheQueueSto),
		      (void *)0, 0,
		      (QEvent *)0);

	QActive_start(AO_raid5,
		      2,
		      l_raid5QueueSto, Q_DIM(l_raid5QueueSto),
		      (void *)0, 0,
		      (QEvent *)0);

	lsa_track_init();
	QF_run();

	return 0;
}

void
lsa_raid_exit(void)
{
	int i;
	for (i = 0; i < Q_DIM(EventPool); i++) {
		struct event_pool *ep = &EventPool[i];
		kfree(ep->sto);
	}
}
