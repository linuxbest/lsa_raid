/*
 * Copyright (C) 2006-2008 Red Hat, Inc. All rights reserved.
 *
 * Module Author: Heinz Mauelshagen (Mauelshagen@RedHat.com)
 *
 * Locking definitions for the device-mapper RAID45 target.
 *
 * This file is released under the GPL.
 *
 */

#ifndef _DM_RAID45_H
#define _DM_RAID45_H

/* Factor out to dm.h! */
#define	STR_LEN(ptr, str)	(ptr), (str), strlen((ptr))

enum dm_lock_type { DM_RAID45_EX, DM_RAID45_SHARED };

struct dm_raid45_locking_type {
	/* Request a lock on a stripe. */
	void* (*lock)(sector_t key, enum dm_lock_type type);

	/* Release a lock on a stripe. */
	void (*unlock)(void *lock_handle);
};

#define DM_PAGE_ORDER 0
#define DM_PAGE_SIZE  (PAGE_SIZE<<DM_PAGE_ORDER)
#define DM_PAGE_SHIFT (PAGE_SHIFT+DM_PAGE_ORDER)

#endif
