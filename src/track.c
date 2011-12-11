#include "qp_port.h"
#include "qp_lsa.h"
#include "md_raid5.h"

Q_DEFINE_THIS_FILE

/* local objects ...........................................................*/
typedef struct TrackTag {
	QHsm super;
	
	struct list_head entry;
	struct page *page;

	struct list_head head;
} Track;

typedef struct TrackRequest {
	struct list_head entry;
	CacheRWEvt evt;
} TrackReq;

static QState Track_initial  (Track *me, QEvent const *e);
static QState Track_top      (Track *me, QEvent const *e);
static QState Track_read     (Track *me, QEvent const *e);
static QState Track_write    (Track *me, QEvent const *e);
static QState Track_dirty    (Track *me, QEvent const *e);
static QState Track_clean    (Track *me, QEvent const *e);

/* track alloc/free---------------------------------------------------------*/
/*..........................................................................*/
static Track * track_alloc(void)
{
	Track *me;
	
	/* allocate the space */
	me = kmalloc(sizeof(*me), GFP_KERNEL);
	Q_ASSERT(me != NULL);
	me->page = alloc_pages(GFP_KERNEL, STRIPE_ORDER);
	Q_ASSERT(me->page != NULL);
	INIT_LIST_HEAD(&me->head);
	
	return me;
}
/*..........................................................................*/
static void track_free(Track *me)
{
	__free_pages(me->page, STRIPE_ORDER);
	kfree(me);
}
/* track request  alloc/free------------------------------------------------*/
/*..........................................................................*/
static TrackReq *track_request_alloc(Track *rt, CacheRWEvt *e)
{
	TrackReq *tq = kmalloc(sizeof(*tq), GFP_KERNEL);
	Q_ASSERT(tq != NULL);
	memcpy(&tq->evt, e, sizeof(CacheRWEvt));
	list_add_tail(&tq->entry, &rt->head);
	return tq;
}
/*..........................................................................*/
static void track_request_free(TrackReq *tq)
{
	kfree(tq);
}
/*..........................................................................*/
static QHsm * Track_ctor(raid5_track *rt)
{
	Track *me = track_alloc();

	/* adding free list */
	list_add_tail(&me->entry, &rt->free);

	/* call QHsm */
	QHsm_ctor(&me->super, (QStateHandler)&Track_initial);
	return (QHsm *)me;
}
/* HSM definition ----------------------------------------------------------*/
/*..........................................................................*/
static QState Track_initial(Track *me, QEvent const *e)
{
	Track *track = me;

	QS_OBJ_DICTIONARY(track);
	QS_OBJ_DICTIONARY(track->page);
	
	QS_SIG_DICTIONARY(CACHE_RW_REQUEST_SIG, me);
	
	return Q_TRAN(&Track_top);
}
/*..........................................................................*/
static QState Track_top(Track *me, QEvent const *e)
{
	switch (e->sig) {
	case CACHE_RW_REQUEST_SIG: {
		CacheRWEvt *pe = (CacheRWEvt *)e;
		if (pe->flags & 1) {
			return Track_write(me, e);
		} else {
			return Track_read(me, e);
		}
		break;
	}
	}
	return Q_SUPER(&QHsm_top);
}
/*..........................................................................*/
static QState Track_clean(Track *me, QEvent const *e)
{
	return Q_TRAN(&QHsm_top);
}
/*..........................................................................*/
static QState Track_dirty(Track *me, QEvent const *e)
{
	return Q_TRAN(&QHsm_top);
}
/*..........................................................................*/
static QState Track_read(Track *me, QEvent const *e)
{
	return Q_TRAN(&QHsm_top);
}
/*..........................................................................*/
static QState Track_write(Track *me, QEvent const *e)
{
	return Q_TRAN(&QHsm_top);
}
/*..........................................................................*/
QHsm * Track_find_or_create(struct raid5_track *rt, uint32_t track)
{
	Track *me = radix_tree_lookup(&rt->tree, track);
	if (me)
		return &me->super;
	if (list_empty(&rt->free))
		return NULL;
	me = list_entry(rt->free.next, Track, entry);
	list_del_init(&me->entry);
	
	/* must not have any request */
	Q_ASSERT(list_empty(&me->head));
	
	return &me->super;
}
/*..........................................................................*/
int lsa_track_init(raid5_track *rt, uint16_t nr)
{
	int i;

	QS_FUN_DICTIONARY(&Track_initial);
	QS_FUN_DICTIONARY(&Track_top);
	QS_FUN_DICTIONARY(&Track_dirty);
	QS_FUN_DICTIONARY(&Track_clean);
	QS_FUN_DICTIONARY(&Track_read);
	QS_FUN_DICTIONARY(&Track_write);
	
	INIT_LIST_HEAD(&rt->free);
	INIT_LIST_HEAD(&rt->used);
	INIT_RADIX_TREE(&rt->tree, GFP_KERNEL);
	
	for (i = 0; i < nr; i ++) {
		Track_ctor(rt);
	}
	
	return 0;
}
/*..........................................................................*/
void lsa_track_exit(raid5_track *rt)
{
       	while (!list_empty(&rt->free)) {
		Track *me = list_entry(rt->free.next, Track, entry);
		list_del(&me->entry);
		track_free(me);
	}
}
