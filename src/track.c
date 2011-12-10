#include "qp_port.h"
#include "qp_lsa.h"
#include "md_raid5.h"

Q_DEFINE_THIS_FILE

/* local objects ...........................................................*/
typedef struct TrackTag {
	QHsm super;
	
	struct list_head entry;
	struct page *page;
} Track;

static QState Track_initial  (Track *me, QEvent const *e);
static QState Track_idle     (Track *me, QEvent const *e);

/*..........................................................................*/
static Track * track_alloc(void)
{
	Track *me;
	
	/* allocate the space */
	me = kmalloc(sizeof(*me), GFP_KERNEL);
	Q_ASSERT(me != NULL);
	me->page = alloc_pages(GFP_KERNEL, STRIPE_ORDER);
	Q_ASSERT(me->page != NULL);

	return me;
}
/*..........................................................................*/
static void track_free(Track *me)
{
	__free_pages(me->page, STRIPE_ORDER);
	kfree(me);
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
/*..........................................................................*/
static QState Track_initial(Track *me, QEvent const *e)
{
	Track *track = me;
	QS_OBJ_DICTIONARY(track);
	QS_OBJ_DICTIONARY(track->page);
	/*QS_SIG_DICTIONARY(, me);*/
	return Q_TRAN(&Track_idle);
}
/*..........................................................................*/
static QState Track_idle(Track *me, QEvent const *e)
{
	switch (e->sig) {
	}
	return Q_TRAN(&QHsm_top);
}
/*..........................................................................*/
int lsa_track_init(raid5_track *rt, uint16_t nr)
{
	int i;

	QS_FUN_DICTIONARY(&Track_initial);
	QS_FUN_DICTIONARY(&Track_idle);
	
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
