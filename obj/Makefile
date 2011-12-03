KDIR          := $(ROOT)/linux26-fdcr
ARCH          := powerpc
CROSS_COMPILE :=${CROSS_COMPILE}

QPC        = ${ROOT}/qpc/
QP_INCDIR  = $(QPC)/include
QEP_SRCDIR = $(QPC)/qep/source
QF_SRCDIR  = $(QPC)/qf/source
QS_SRCDIR  = $(QPC)/qs/source
RAID5_DIR  = $(ROOT)/dm-raid456/src/

EXTRA_CFLAGS += -I$(RAID5_DIR) -I$(QP_INCDIR) -I${QF_SRCDIR}

CONF = spy

vpath-y += ${QF_SRCDIR}
vpath-y += ${QS_SRCDIR}
vpath-y += ${QEP_SRCDIR}
vpath-y += ${RAID5_DIR}

ifneq ($(KERNELRELEASE),)
	obj-m := lsa.o
endif

default:
	make -C $(KDIR) ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} SUBDIRS=$(PWD) modules GITVERSION="git-g$(shell git describe --dirty --always)"

clean:
	make -C $(KDIR) SUBDIRS=$(PWD) clean
	
qf_objs += qa_defer.o
qf_objs += qa_fifo.o
qf_objs += qa_lifo.o
qf_objs += qa_get_.o
qf_objs += qa_sub.o
qf_objs += qa_usub.o
qf_objs += qa_usuba.o
qf_objs += qeq_init.o
qf_objs += qeq_fifo.o
qf_objs += qeq_lifo.o
qf_objs += qeq_get.o
qf_objs += qf_act.o
qf_objs += qf_gc.o
qf_objs += qf_log2.o
qf_objs += qf_new.o
qf_objs += qf_pool.o
qf_objs += qf_psini.o
qf_objs += qf_pspub.o
qf_objs += qf_pwr2.o
qf_objs += qf_tick.o
qf_objs += qmp_get.o
qf_objs += qmp_init.o
qf_objs += qmp_put.o
qf_objs += qte_ctor.o
qf_objs += qte_arm.o
qf_objs += qte_darm.o
qf_objs += qte_rarm.o

ifeq ($(CONF),spy)
EXTRA_CFLAGS += -DQ_SPY=1
qs_objs +=  qs.o
qs_objs +=  qs_.o
qs_objs +=  qs_blk.o
qs_objs +=  qs_byte.o
qs_objs +=  qs_f32.o
qs_objs +=  qs_f64.o
qs_objs +=  qs_u64.o
qs_objs +=  qs_mem.o
qs_objs +=  qs_str.o
endif

qep_objs +=  qep.o
qep_objs +=  qfsm_ini.o
qep_objs +=  qfsm_dis.o
qep_objs +=  qhsm_ini.o
qep_objs +=  qhsm_dis.o
qep_objs +=  qhsm_top.o
qep_objs +=  qhsm_in.o

qp_port += bsp.o
qp_port += qf_port.o

lsa-objs := ${qf_objs} ${qep_objs} ${qs_objs} ${qp_port}
lsa-objs += md_raid5.o qp_lsa.o cache.o
