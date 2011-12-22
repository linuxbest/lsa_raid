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
	uint32_t track;
	raid5_conf_t *conf;
	struct list_head head;
} Track;

typedef struct TrackRequest {
	struct list_head entry;
	CacheRWEvt evt;
} TrackReq;

/*
 * unused:  no data in page, bitmap is cleared.
 * ioin:    the data in from the io layer.
 * ioout:   the data out from the io layer. 
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
static QState Track_ioin     (Track *me, QEvent const *e);
static QState Track_ioout    (Track *me, QEvent const *e);

static QState Track_iohandle (Track *me, QEvent const *e);
static QState Track_seghandle(Track *me, QEvent const *e);

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
/* must call under cache active object */
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
	
	QS_SIG_DICTIONARY(CACHE_WRITE_REQUEST_SIG, me);
	QS_SIG_DICTIONARY(CACHE_READ_REQUEST_SIG,  me);
	QS_SIG_DICTIONARY(CACHE_WRITE_DONE_SIG,    me);
	QS_SIG_DICTIONARY(CACHE_READ_DONE_SIG,     me);
	QS_SIG_DICTIONARY(SEG_READ_REPLY_SIG,      me);
	QS_SIG_DICTIONARY(SEG_WRITE_REPLY_SIG,     me);

	/* adding free list */
	list_add_tail(&me->entry, &rt->free);

	/* call QHsm */
	QHsm_ctor(&me->super, (QStateHandler)&Track_initial);
	return &me->super;
}
/* HSM definition ----------------------------------------------------------*/
/*..........................................................................*/
static QState Track_initial(Track *me, QEvent const *e)
{
	return Q_TRAN(&Track_unused);
}
/*..........................................................................*/
static QState Track_read_req(Track *me, QEvent const *e)
{
	TrackReq *req = track_request_alloc(me, (CacheRWEvt *)e);
	SegmentEvt *pe = Q_NEW(SegmentEvt, SEG_READ_REQUEST_SIG);
	pe->track = me->track;
	pe->me    = me;
	pe->conf  = me->conf;
	pe->page  = me->page;
	QACTIVE_POST(AO_segment, (QEvent *)pe, AO_cache);
	return Q_TRAN(&Track_segin);
}
/*..........................................................................*/
static QState Track_unused(Track *me, QEvent const *e)
{
	switch (e->sig) {
	case CACHE_WRITE_REQUEST_SIG:
		/* TODO */
		break;
		
	case CACHE_READ_REQUEST_SIG:
		return Track_read_req(me, e);
		
	case CACHE_WRITE_DONE_SIG:
	case CACHE_READ_DONE_SIG:
	case SEG_WRITE_REPLY_SIG:
	case SEG_READ_REPLY_SIG:
		break;
	}
	return Q_SUPER(&QHsm_top);
}
/*..........................................................................*/
static QState Track_dirty(Track *me, QEvent const *e)
{
	switch (e->sig) {
	}
	return Q_SUPER(&QHsm_top);
}
/*..........................................................................*/
static QState Track_clean(Track *me, QEvent const *e)
{
	switch (e->sig) {
	}
	return Q_SUPER(&QHsm_top);
}
/*..........................................................................*/
static QState Track_segin(Track *me, QEvent const *e)
{
	switch (e->sig) {
	}
	return Q_SUPER(&QHsm_top);
}
/*..........................................................................*/
static QState Track_segout(Track *me, QEvent const *e)
{
	switch (e->sig) {
	}
	return Q_SUPER(&QHsm_top);
}
/*..........................................................................*/
static QState Track_ioin(Track *me, QEvent const *e)
{
	switch (e->sig) {
	}
	return Q_SUPER(&QHsm_top);
}
/*..........................................................................*/
static QState Track_ioout(Track *me, QEvent const *e)
{
	switch (e->sig) {
	}
	return Q_SUPER(&QHsm_top);
}
/*..........................................................................*/
static QHsm * Track_find_or_create(raid5_conf_t *conf, uint32_t track)
{
	struct raid5_track *rt = raid5_track_conf(conf);
	int res;
	Track *me;

	me = radix_tree_lookup(&rt->tree, track);
	if (me) {
		Q_ASSERT(me->track == track);
		return &me->super;
	}
	if (list_empty(&rt->free))
		return NULL;
	me = list_entry(rt->free.next, Track, entry);
	list_del_init(&me->entry);
	me->track = track;
	me->conf  = conf;

	/* must not have any request */
	Q_ASSERT(list_empty(&me->head));

	/* insert into tree */
	res = radix_tree_insert(&rt->tree, track, me);
	Q_ASSERT(res == 0);
	
	return &me->super;
}
/* export function ---------------------------------------------------------*/
/*..........................................................................*/
void Track_dispatch(raid5_conf_t *conf, QEvent const *e)
{
	CacheRWEvt *pe = (CacheRWEvt *)e;
	QHsm *track = Track_find_or_create(conf, pe->track);
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
	QS_FUN_DICTIONARY(&Track_ioin);
	QS_FUN_DICTIONARY(&Track_ioout);
	
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
