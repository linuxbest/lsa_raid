#include "qp_port.h"
#include "qp_lsa.h"
#include "md_raid5.h"

Q_DEFINE_THIS_FILE

/* local objects ...........................................................*/
typedef struct TrackTag {
	QHsm super;
	
	struct list_head entry;
	struct page *page;
	uint8_t bitmap[1<<(STRIPE_SHIFT-(9+3))];
	struct list_head head;
} Track;

typedef struct TrackRequest {
	struct list_head entry;
	CacheRWEvt evt;
} TrackReq;

/*
 * unused:  no data in page, bitmap is cleared.
 * segin:   the data is reading from segment.
 * segout:  the dirty data is try write to segment.
 * dirty:   have dirty data in page, may not full data.
 * clean:   have data in page, may not full data.
 *
 */
static QState Track_initial  (Track *me, QEvent const *e);
static QState Track_unused   (Track *me, QEvent const *e);
static QState Track_dirty    (Track *me, QEvent const *e);
static QState Track_clean    (Track *me, QEvent const *e);
static QState Track_segin    (Track *me, QEvent const *e);
static QState Track_segout   (Track *me, QEvent const *e);

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
	Track *track = me;

	QS_OBJ_DICTIONARY(track);
	QS_OBJ_DICTIONARY(track->page);
	
	QS_SIG_DICTIONARY(CACHE_RW_REQUEST_SIG, me);

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
	return Q_TRAN(&Track_unused);
}
/*..........................................................................*/
static QState Track_unused(Track *me, QEvent const *e)
{
	switch (e->sig) {
	case CACHE_RW_REQUEST_SIG: {
		CacheRWEvt *pe = (CacheRWEvt *)e;
		if (pe->flags & 1) { /* WRITE */
			return Q_TRAN(&Track_dirty);
		} else {
			return Q_TRAN(&Track_segin);
		}
	}
	}
	return Q_SUPER(&QHsm_top);
}
/*..........................................................................*/
static QState Track_dirty(Track *me, QEvent const *e)
{
	switch (e->sig) {
	case Q_ENTRY_SIG: {
	}
	}
	return Q_SUPER(&QHsm_top);
}
/*..........................................................................*/
static QState Track_clean(Track *me, QEvent const *e)
{
	return Q_SUPER(&QHsm_top);
}
/*..........................................................................*/
static QState Track_segin(Track *me, QEvent const *e)
{
	switch (e->sig) {
	case Q_ENTRY_SIG: {
		/* sending request into segment buffer */
		return Q_HANDLED();
	}
	}
	return Q_SUPER(&QHsm_top);
}
/*..........................................................................*/
static QState Track_segout(Track *me, QEvent const *e)
{
	return Q_SUPER(&QHsm_top);
}
/*..........................................................................*/
static QHsm * Track_find_or_create(struct raid5_track *rt, uint32_t track)
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
/* export function ---------------------------------------------------------*/
/*..........................................................................*/
void Track_dispatch(struct raid5_track *rt, QEvent const *e)
{
	CacheRWEvt *pe = (CacheRWEvt *)e;
	QHsm *track = Track_find_or_create(rt, pe->track);
	/* TODO: handle track empty */
	Q_ASSERT(track);
	QHsm_dispatch(track, e);
}
/*..........................................................................*/
int lsa_track_init(raid5_track *rt, uint16_t nr)
{
	int i;

	QS_FUN_DICTIONARY(&Track_initial);
	QS_FUN_DICTIONARY(&Track_unused);
	QS_FUN_DICTIONARY(&Track_dirty);
	QS_FUN_DICTIONARY(&Track_clean);
	QS_FUN_DICTIONARY(&Track_segin);
	QS_FUN_DICTIONARY(&Track_segout);
	
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
