#include "qp_port.h"
#include "qp_lsa.h"
#include "md_raid5.h"

Q_DEFINE_THIS_FILE

/* local objects ...........................................................*/
typedef struct StripeTag {
	QHsm super;
	
	struct list_head entry;
} Stripe;

static QState Stripe_initial  (Stripe *me, QEvent const *e);

/*..........................................................................*/
static Stripe *stripe_alloc(void)
{
	Stripe *me = kmalloc(sizeof(*me), GFP_KERNEL);
	return me;
}
static void stripe_free(Stripe *me)
{
	kfree(me);
}
/*..........................................................................*/
static QHsm *Stripe_ctor(raid5_segment *rseg)
{
	Stripe * me;
	Stripe * seg;

	/* allocate the memory */
	me = seg = stripe_alloc();
	Q_ASSERT(me != NULL);
	
	QS_OBJ_DICTIONARY(seg);
	/*QS_OBJ_DICTIONARY(seg->*/
	
	QS_SIG_DICTIONARY(SEG_READ_REQUEST_SIG,   me);
	QS_SIG_DICTIONARY(SEG_WRITE_REQUEST_SIG,  me);
	
	/* adding free list */
	list_add_tail(&me->entry, &rseg->free);
	
	/* call QHsm */
	QHsm_ctor(&me->super, (QStateHandler)&Stripe_initial);
	return &me->super;
}
/* HSM definition ----------------------------------------------------------*/
/*..........................................................................*/
static QState Stripe_initial(Stripe *me, QEvent const *e)
{
	return Q_SUPER(&QHsm_top);
}
/* export function ---------------------------------------------------------*/
/*..........................................................................*/
int lsa_stripe_init(raid5_segment *rseg, uint16_t nr)
{
	int i;

	QS_FUN_DICTIONARY(&Stripe_initial);

	INIT_LIST_HEAD(&rseg->free);
	INIT_LIST_HEAD(&rseg->used);
	INIT_RADIX_TREE(&rseg->tree, GFP_KERNEL);
	
	for (i = 0; i < nr; i ++) {
		Stripe_ctor(rseg);
	}

	return 0;
}
/*..........................................................................*/
void lsa_stripe_exit(raid5_segment *rseg)
{
	while (!list_empty(&rseg->free)) {
		Stripe *me = list_entry(rseg->free.next, Stripe, entry);
		list_del(&me->entry);
		stripe_free(me);
	}
}
