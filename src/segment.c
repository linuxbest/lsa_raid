#include "qp_port.h"
#include "qp_lsa.h"
#include "md_raid5.h"

Q_DEFINE_THIS_FILE

/* local objects ...........................................................*/
typedef struct SegmentTag {
	QHsm super;
	
	struct list_head entry;
} Segment;

static QState Segment_initial  (Segment *me, QEvent const *e);

/*..........................................................................*/
static Segment *segment_alloc(void)
{
	Segment *me = kmalloc(sizeof(*me), GFP_KERNEL);
	return me;
}
static void segment_free(Segment *me)
{
	kfree(me);
}
/*..........................................................................*/
static QHsm *Segment_ctor(raid5_segment *rseg)
{
	Segment * me;
	Segment * seg;

	/* allocate the memory */
	me = seg = segment_alloc();
	Q_ASSERT(me != NULL);
	
	QS_OBJ_DICTIONARY(seg);
	/*QS_OBJ_DICTIONARY(seg->*/
	
	/* adding free list */
	list_add_tail(&me->entry, &rseg->free);
	
	/* call QHsm */
	QHsm_ctor(&me->super, (QStateHandler)&Segment_initial);
	return &me->super;
}
/* HSM definition ----------------------------------------------------------*/
/*..........................................................................*/
static QState Segment_initial(Segment *me, QEvent const *e)
{
	return Q_SUPER(&QHsm_top);
}
/* export function ---------------------------------------------------------*/
/*..........................................................................*/
int lsa_segment_init(raid5_segment *rseg, uint16_t nr)
{
	int i;

	QS_FUN_DICTIONARY(&Segment_initial);

	INIT_LIST_HEAD(&rseg->free);
	INIT_LIST_HEAD(&rseg->used);
	INIT_RADIX_TREE(&rseg->tree, GFP_KERNEL);
	
	for (i = 0; i < nr; i ++) {
		Segment_ctor(rseg);
	}

	return 0;
}
/*..........................................................................*/
void lsa_segment_exit(raid5_segment *rseg)
{
	while (!list_empty(&rseg->free)) {
		Segment *me = list_entry(rseg->free.next, Segment, entry);
		list_del(&me->entry);
		segment_free(me);
	}
}
