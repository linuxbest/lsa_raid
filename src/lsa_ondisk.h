#ifndef _LSA_ONDISK_STRUCT_
#define _LSA_ONDISK_STRUCT_

typedef struct {
	/* word 0 */
	uint32_t seg_id;
	/* word 1 */
	uint8_t  seg_column;
	uint8_t  age;
	uint8_t  status;
	uint8_t  activity;
	/* word 2 */
	uint16_t offset;
	uint16_t length;
	/* word 3 */
	uint16_t unused0;
	uint8_t  unused1;
	uint8_t  crc;
} __attribute__ ((packed)) lsa_entry_t;

#endif
