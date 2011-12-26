#include "qp_port.h"
#include "qp_lsa.h"
#include "md_raid5.h"

#include "lsa_ondisk.h"

Q_DEFINE_THIS_FILE

/* local objects ...........................................................*/
typedef struct EntryTag {
	QHsm super;

	lsa_entry_t      e;
	struct list_head entry;
} Entry;

static QState Entry_initial  (Entry *me, QEvent const *e);
/*..........................................................................*/
static Entry *entry_alloc(void)
{
	Entry *me = kmalloc(sizeof(*me), GFP_KERNEL);
	return me;
}
/*..........................................................................*/
static void entry_free(Entry *me)
{
	kfree(me);
}
/*..........................................................................*/
static QHsm *Entry_ctor(raid5_entry_t *rentry)
{
	Entry *me;
	Entry *entry;

	/* allocate the memory */
	me = entry = entry_alloc();
	Q_ASSERT(me != NULL);

	QS_OBJ_DICTIONARY(entry);
	/* QS_OBJ_DICTIONARY(entry->x); */
	
	QS_SIG_DICTIONARY(DIR_REQUEST_SIG, me);
	QS_SIG_DICTIONARY(DIR_UPDATE_SIG,  me);
	QS_SIG_DICTIONARY(DIR_INSERT_SIG,  me);
	
	/* adding free list */
	list_add_tail(&me->entry, &rentry->free);
	
	/* call QHsm */
	QHsm_ctor(&me->super, (QStateHandler)&Entry_initial);

	return &me->super;
}
/* HSM definition ----------------------------------------------------------*/
/*..........................................................................*/
static QState Entry_initial(Entry *me, QEvent const *e)
{
	return Q_SUPER(&QHsm_top);
}
/* export function ---------------------------------------------------------*/
/*..........................................................................*/
int lsa_entry_init(raid5_entry_t *rentry, uint16_t nr)
{
	int i;
	
	QS_FUN_DICTIONARY(&Entry_initial);
	
	INIT_LIST_HEAD(&rentry->free);
	INIT_LIST_HEAD(&rentry->used);
	INIT_RADIX_TREE(&rentry->tree, GFP_KERNEL);

	for (i = 0; i < nr; i ++) {
		Entry_ctor(rentry);
	}

	return 0;
}
/*..........................................................................*/
void lsa_entry_exit(raid5_entry_t *rentry)
{
	while (!list_empty(&rentry->free)) {
		Entry *me = list_entry(rentry->free.next, Entry, entry);
		list_del(&me->entry);
		entry_free(me);
	}
}
