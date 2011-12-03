#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "qf_pkg.h"
#include "qassert.h"

#include "qp_lsa.h"
#include "bsp.h"

Q_DEFINE_THIS_MODULE(qf_port)

#ifdef Q_SPY
static uint8_t l_ticker;
#endif

/* Global objects ----------------------------------------------------------*/
DEFINE_SPINLOCK(QF_lock);

/* Local objects -----------------------------------------------------------*/
static uint8_t l_running;
static atomic_t AO_threads;
static DECLARE_WAIT_QUEUE_HEAD(AO_wait);
static DECLARE_COMPLETION(tick_done);
/*..........................................................................*/
const char *QF_getPortVersion(void)
{
	static const char Q_ROM version[] =  "4.3.00";
	return version;
}
/*..........................................................................*/
void QF_init(void)
{
}
/*..........................................................................*/
static int QF_tick_thread(void *arg)
{
	complete(&tick_done);
	while (l_running) {
		schedule_timeout(HZ*10);
		if (kthread_should_stop())
			break;
		QF_TICK(&l_ticker);    /* process a time tick */
	}
	QF_onCleanup(); /* invoke cleanup callback */
	complete(&tick_done);
	return 0;
}
/*..........................................................................*/
void QF_run(void)
{
	QF_onStartup(); /* invoke startup callback */

	QS_OBJ_DICTIONARY(&l_ticker);  /* the QS dictionary for the ticker */
	
	l_running = (uint8_t)1;
	kthread_run(QF_tick_thread, NULL, "AO_tick");
	wait_for_completion(&tick_done);
}
/*..........................................................................*/
void QF_stop(void)
{
	l_running = (uint8_t)0;
	wait_for_completion(&tick_done);
}
void QF_exit(void)
{
	QF_PUBLISH(Q_NEW(QEvent, TERMINATE_SIG), (void *)0);
	QF_stop();
	wait_event(AO_wait, atomic_read(&AO_threads) == 0);
}
/*..........................................................................*/
static int thread_routine(void *arg)
{
	atomic_inc(&AO_threads);

	((QActive *)arg)->running = (uint8_t)1;
	while (((QActive *)arg)->running) {
		QEvent const *e = QActive_get_((QActive *)arg);
		QF_ACTIVE_DISPATCH_(&((QActive *)arg)->super, e);
		QF_gc(e);
	}
	/*QF_remove_((QActive *)arg);*/

	if (atomic_dec_return(&AO_threads))
		wake_up(&AO_wait);
	return 0;
}
/*..........................................................................*/
void QActive_start(QActive *me, uint8_t prio,
		QEvent const *qSto[], uint32_t qLen,
		void *stkSto, uint32_t stkSize,
		QEvent const *ie)
{
	char buf[32];
	sprintf(buf, "AO%d", prio);
	QEQueue_init(&me->eQueue, qSto, (QEQueueCtr)qLen);
	init_waitqueue_head(&me->osObject);

	me->prio = prio;
	QF_add_(me);
	QF_ACTIVE_INIT_(&me->super, ie);

	QS_FLUSH();

	me->thread = kthread_run(thread_routine, me, buf);
}
/*..........................................................................*/
void QActive_stop(QActive *me)
{
	me->running = (uint8_t)0;
	/*kthread_stop(me->thread);*/
}
