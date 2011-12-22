#include "qp_port.h"
#include "qp_lsa.h"
#include "md_raid5.h"

#include "lsa_ondisk.h"

Q_DEFINE_THIS_FILE

/* local objects ...........................................................*/
typedef struct EntryTag {
	QHsm super;

	lsa_entry_t entry;
} Entry;

