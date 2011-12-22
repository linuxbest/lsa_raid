#include "qp_port.h"
#include "qp_lsa.h"
#include "md_raid5.h"

Q_DEFINE_THIS_FILE

typedef struct SegmentTag {
	QActive super;
} Segment;

static QState Segment_initial (Segment *me, QEvent const *e);
static QState Segment_final   (Segment *me, QEvent const *e);
static QState Segment_idle    (Segment *me, QEvent const *e);

static Segment l_segment;

QActive *const AO_segment = (QActive *)&l_segment;

/*..........................................................................*/
void Segment_ctor(void)
{
	Segment *me = &l_segment;
	QActive_ctor(&me->super, (QStateHandler)(Segment_initial));
}
/* HSM definition ----------------------------------------------------------*/
/*..........................................................................*/
static QState Segment_initial(Segment *me, QEvent const *e)
{
	QActive_subscribe((QActive *)me, TERMINATE_SIG);

	QS_OBJ_DICTIONARY(&l_segment);

	QS_FUN_DICTIONARY(&Segment_initial);
	QS_FUN_DICTIONARY(&Segment_final);
	QS_FUN_DICTIONARY(&Segment_idle);

	QS_SIG_DICTIONARY(SEG_READ_REQUEST_SIG,  &l_segment);
	QS_SIG_DICTIONARY(SEG_WRITE_REQUEST_SIG, &l_segment);
	
	return Q_TRAN(&Segment_idle);
}
/*..........................................................................*/
static QState Segment_final(Segment *me, QEvent const *e)
{
	switch (e->sig) {
	case Q_ENTRY_SIG:
		QActive_stop(&me->super);
		return Q_HANDLED();
	}
	return Q_SUPER(&QHsm_top);
}
/*..........................................................................*/
static QState Segment_idle(Segment *me, QEvent const *e)
{
	switch (e->sig) {
	case TERMINATE_SIG:
		return Q_TRAN(&Segment_final);
		
	case SEG_READ_REQUEST_SIG:
		return Q_HANDLED();

	case SEG_WRITE_REQUEST_SIG:
		return Q_HANDLED();
	}
	return Q_SUPER(&QHsm_top);
}
