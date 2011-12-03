/*****************************************************************************
* Product:  QF/C, port to 80x86, Linux/P-threads, gcc
* Last Updated for Version: 4.3.00
* Date of the Last Update:  Oct 31, 2011
*
*                    Q u a n t u m     L e a P s
*                    ---------------------------
*                    innovating embedded systems
*
* Copyright (C) 2002-2011 Quantum Leaps, LLC. All rights reserved.
*
* This software may be distributed and modified under the terms of the GNU
* General Public License version 2 (GPL) as published by the Free Software
* Foundation and appearing in the file GPL.TXT included in the packaging of
* this file. Please note that GPL Section 2[b] requires that all works based
* on this software must also be made publicly available under the terms of
* the GPL ("Copyleft").
*
* Alternatively, this software may be distributed and modified under the
* terms of Quantum Leaps commercial licenses, which expressly supersede
* the GPL and are specifically designed for licensees interested in
* retaining the proprietary status of their code.
*
* Contact information:
* Quantum Leaps Web site:  http://www.quantum-leaps.com
* e-mail:                  info@quantum-leaps.com
*****************************************************************************/
#ifndef qf_port_h
#define qf_port_h

#include <linux/ctype.h> 
#include <linux/types.h> 
#include <linux/kernel.h> 
#include <linux/kthread.h> 

                                      /* Linux event queue and thread types */
#define QF_EQUEUE_TYPE              QEQueue
#define QF_OS_OBJECT_TYPE           wait_queue_head_t
#define QF_THREAD_TYPE              struct task_struct *

                 /* The maximum number of active objects in the application */
#define QF_MAX_ACTIVE               63
                    /* The maximum number of event pools in the application */
#define QF_MAX_EPOOL                8
                     /* various QF object sizes configuration for this port */
#define QF_EVENT_SIZ_SIZE           4
#define QF_EQUEUE_CTR_SIZE          4
#define QF_MPOOL_SIZ_SIZE           4
#define QF_MPOOL_CTR_SIZE           4
#define QF_TIMEEVT_CTR_SIZE         4

#define QF_CRIT_STAT_TYPE        unsigned long
#define QF_INT_KEY_TYPE          unsigned long
#define QF_INT_LOCK(dummy)       spin_lock_irqsave(&QF_lock, dummy)
#define QF_INT_UNLOCK(dummy)     spin_unlock_irqrestore(&QF_lock, dummy)

#include "qep_port.h"                                           /* QEP port */
#include "qequeue.h"                             /* Linux needs event-queue */
#include "qmpool.h"                              /* Linux needs memory-pool */
#include "qf.h"                 /* QF platform-independent public interface */


/*****************************************************************************
* interface used only inside QF, but not in applications
*/
                                      /* OS-object implementation for Linux */
#define QACTIVE_EQUEUE_WAIT_(me_)    do { \
	spin_unlock_irqrestore(&QF_lock, critStat_); \
	wait_event((me_)->osObject, (me_)->eQueue.frontEvt != (QEvent *)0); \
	spin_lock_irqsave(&QF_lock, critStat_); \
} while (0)
#define QACTIVE_EQUEUE_SIGNAL_(me_)  wake_up(&(me_)->osObject)
#define QACTIVE_EQUEUE_ONEMPTY_(me_) ((void)0)

                                         /* native QF event pool operations */
#define QF_EPOOL_TYPE_              QMPool
#define QF_EPOOL_INIT_(p_, poolSto_, poolSize_, evtSize_) \
    QMPool_init(&(p_), poolSto_, poolSize_, evtSize_)
#define QF_EPOOL_EVENT_SIZE_(p_)    ((p_).blockSize)
#define QF_EPOOL_GET_(p_, e_)       ((e_) = (QEvent *)QMPool_get(&(p_)))
#define QF_EPOOL_PUT_(p_, e_)       (QMPool_put(&(p_), e_))

extern spinlock_t QF_lock;
#endif                                                         /* qf_port_h */
