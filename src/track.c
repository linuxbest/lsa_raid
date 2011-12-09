#include "qp_port.h"
#include "qp_lsa.h"
#include "md_raid5.h"

Q_DEFINE_THIS_FILE

/* local objects ...........................................................*/
typedef struct TrackTag {
	QHsm super;
	
	struct list_head entry;
} Track;

static QState Track_initial  (Track *me, QEvent const *e);

static LIST_HEAD(free);

/*..........................................................................*/
QHsm *Track_ctor(uint32_t track)
{
	Track *me = NULL;	/* TODO */
	
	QHsm_ctor(&me->super, (QStateHandler)&Track_initial);
	return (QHsm *)me;
}
/*..........................................................................*/
static QState Track_initial(Track *me, QEvent const *e)
{
	/*QS_OBJ_DICTIONARY();*/
	/*QS_SIG_DICTIONARY(, me);*/
	/* TODO */
	return Q_TRAN(&QHsm_top);
}
/*..........................................................................*/
int  lsa_track_init(void)
{
	QS_FUN_DICTIONARY(&Track_initial);
	return 0;
}

/*..........................................................................*/
void lsa_track_exit(void)
{
}
