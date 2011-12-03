#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "qp_port.h"

//#include "dpp.h"
#include "bsp.h"

#ifdef Q_SPY
#include <linux/netpoll.h>
#include <linux/inet.h>
struct netpoll np;
#define QS_SPY_BLOCK  512
#define QS_SPY_SIZE 16384
static uint8_t *qsBuf;
static int idle_running = 0;
static DECLARE_COMPLETION(idle_done);
#endif

Q_DEFINE_THIS_MODULE(bsp)

/*..........................................................................*/
#ifdef Q_SPY
static void QS_send(uint8_t const *block, uint16_t nBytes)
{
	if (np.dev)
		netpoll_send_udp(&np, block, nBytes);
}
static int idleThread(void *arg)
{
	complete(&idle_done);
	while (idle_running) {
		QF_INT_KEY_TYPE dummy;
		uint8_t const *block;
		uint16_t nBytes = QS_SPY_BLOCK;
		QF_INT_LOCK(dummy);
		block = QS_getBlock(&nBytes);
		QF_INT_UNLOCK(dummy);

		QS_send(block, nBytes);
		schedule_timeout(HZ);
	}
	complete(&idle_done);

	return 0;
}
#endif
/*..........................................................................*/
void QF_onStartup(void)
{
#ifdef Q_SPY
	int rc;
	char *target_config = "@/,6601@192.168.5.33/00:13:72:f7:14:73";

	np.name = "QSPY";
	strlcpy(np.dev_name, "eth0", IFNAMSIZ);
	np.local_port  = 6600;
	np.remote_port = 6601;
	memset(np.remote_mac, 0xff, ETH_ALEN);

	rc = netpoll_parse_options(&np, target_config);
	if (rc == 0) {
		rc = netpoll_setup(&np);
	}
	if (rc)
		np.dev = NULL;
	printk("rc: %d, %p\n", rc, np.dev);

	idle_running = 1;
	kthread_run(idleThread, NULL, "AO_Idle");
	complete(&idle_done);
#endif
}
/*..........................................................................*/
void QF_onCleanup(void)
{
#ifdef Q_SPY
	idle_running = 0;
	complete(&idle_done);
	QS_onFlush();
	if (np.dev)
		netpoll_cleanup(&np);
	if (qsBuf)
		kfree(qsBuf);
#endif
}
/*..........................................................................*/
void QS_onFlush(void)
{
#ifdef Q_SPY
	uint8_t const *block;
	uint16_t nBytes = QS_SPY_BLOCK;
	while (np.dev && (block = QS_getBlock(&nBytes)) != (uint8_t *)0) {
		QS_send(block, nBytes);
		nBytes = QS_SPY_BLOCK;
	}
#endif
}
/*..........................................................................*/
#ifdef Q_SPY
uint8_t QS_onStartup(void const *arg) 
{
    qsBuf = kmalloc(QS_SPY_SIZE, GFP_KERNEL);
    if (qsBuf == NULL)
	    return 0;

    QS_initBuf(qsBuf, QS_SPY_SIZE);

    QS_FILTER_ON(QS_ALL_RECORDS);
  
    QS_BEGIN_NOCRIT_(QS_QEP_RESERVED0, (void *)0, (void *)0)
	    QS_U8_(QS_TIME_SIZE);
	    QS_U8_(QS_OBJ_PTR_SIZE);
	    QS_U8_(QS_FUN_PTR_SIZE);
	    QS_U8_(Q_SIGNAL_SIZE);
	    QS_U8_(QF_EQUEUE_CTR_SIZE);
	    QS_U8_(QF_EQUEUE_CTR_SIZE);
	    QS_U8_(QF_MPOOL_CTR_SIZE);
	    QS_U8_(QF_MPOOL_SIZ_SIZE);
	    QS_U8_(QF_TIMEEVT_CTR_SIZE);
    QS_END_NOCRIT_();

    return 1;
}
/*..........................................................................*/
QSTimeCtr QS_onGetTime(void)
{
#if 0
	return get_cycles();
#else
	return jiffies;
#endif
}
#endif
/*..........................................................................*/
void Q_onAssert(char const Q_ROM * const Q_ROM_VAR file, int line)
{
	printk("Q_onAssert, %s:%d\n", file, line);
}
void BSP_init(int argc, char *argv[])
{
	char const *hostAndPort = "localhost:6601";
	QS_INIT(hostAndPort);
	printk("QEP %s\nQF  %s\n", QEP_getVersion(),
			QF_getVersion());
}
/*..........................................................................*/
void BSP_busyDelay(void)
{
}
/*..........................................................................*/
int module_qp_init(void)
{
	//main(0, NULL);
	return 0;
}
/*..........................................................................*/
void module_qp_exit(void)
{
	QF_exit();
}

/*..........................................................................*/
module_init(module_qp_init);
module_exit(module_qp_exit);
MODULE_LICENSE("GPL");
