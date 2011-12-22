#include "qp_port.h"
#include "qp_lsa.h"
#include "md_raid5.h"

Q_DEFINE_THIS_FILE

typedef struct DirtoryTag {
	QActive super;
} Dirtory;

static QState Dirtory_initial (Dirtory *me, QEvent const *e);
static QState Dirtory_final   (Dirtory *me, QEvent const *e);
static QState Dirtory_idle    (Dirtory *me, QEvent const *e);

static Dirtory l_dirtory;

QActive *const AO_dirtory = (QActive *)&l_dirtory;

/*..........................................................................*/
void Dirtory_ctor(void)
{
	Dirtory *me = &l_dirtory;
	QActive_ctor(&me->super, (QStateHandler)(Dirtory_initial));
}
/* HSM definition ----------------------------------------------------------*/
/*..........................................................................*/
static QState Dirtory_initial(Dirtory *me, QEvent const *e)
{
	QActive_subscribe((QActive *)me, TERMINATE_SIG);

	QS_OBJ_DICTIONARY(&l_dirtory);
	
	QS_FUN_DICTIONARY(&Dirtory_initial);
	QS_FUN_DICTIONARY(&Dirtory_final);
	QS_FUN_DICTIONARY(&Dirtory_idle);

	QS_SIG_DICTIONARY(DIR_REQUEST_SIG, &l_dirtory);
	QS_SIG_DICTIONARY(DIR_UPDATE_SIG,  &l_dirtory);
	
	return Q_TRAN(&Dirtory_idle);
}
/*..........................................................................*/
static QState Dirtory_final(Dirtory *me, QEvent const *e)
{
	switch (e->sig) {
	case Q_ENTRY_SIG:
		QActive_stop(&me->super);
		return Q_HANDLED();
	}
	return Q_SUPER(&QHsm_top);
}
/*..........................................................................*/
static QState Dirtory_idle(Dirtory *me, QEvent const *e)
{
	switch (e->sig) {
	case TERMINATE_SIG:
		return Q_TRAN(&Dirtory_final);
		
	case DIR_REQUEST_SIG:
		/* get the dirtory entry */
		return Q_HANDLED();
		
	case DIR_UPDATE_SIG:
		/* update the dirtory entry */
		return Q_HANDLED();
	}
	return Q_SUPER(&QHsm_top);
}
