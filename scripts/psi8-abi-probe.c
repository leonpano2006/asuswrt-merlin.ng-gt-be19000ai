/* Compile-only ABI probe. Never linked into firmware or loaded on a device. */
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/page-flags.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/vmstat.h>

#define ABI_VALUE(name, expression) \
 const unsigned long psi8_abi_##name = (unsigned long)(expression)
#define ABI_CONSTANT(name) const unsigned long psi8_abi_##name = (unsigned long)(name)
ABI_CONSTANT(BITS_PER_LONG);
ABI_CONSTANT(NR_PAGEFLAGS);
ABI_CONSTANT(__NR_PAGEFLAGS);
ABI_CONSTANT(ZONES_WIDTH);
ABI_CONSTANT(ZONES_SHIFT);
ABI_CONSTANT(ZONES_PGOFF);
ABI_CONSTANT(ZONES_PGSHIFT);
ABI_CONSTANT(ZONES_MASK);
ABI_CONSTANT(NODES_WIDTH);
ABI_CONSTANT(NODES_SHIFT);
ABI_CONSTANT(NODES_PGOFF);
ABI_CONSTANT(NODES_PGSHIFT);
ABI_CONSTANT(NODES_MASK);
ABI_CONSTANT(SECTIONS_WIDTH);
ABI_CONSTANT(SECTIONS_PGOFF);
ABI_CONSTANT(SECTIONS_PGSHIFT);
ABI_CONSTANT(SECTIONS_MASK);
ABI_CONSTANT(LAST_CPUPID_WIDTH);
ABI_CONSTANT(LAST_CPUPID_SHIFT);
ABI_CONSTANT(LAST_CPUPID_PGOFF);
ABI_CONSTANT(LAST_CPUPID_PGSHIFT);
ABI_CONSTANT(LAST_CPUPID_MASK);
ABI_CONSTANT(ZONEID_SHIFT);
ABI_CONSTANT(ZONEID_PGOFF);
ABI_CONSTANT(ZONEID_PGSHIFT);
ABI_CONSTANT(ZONEID_MASK);
ABI_CONSTANT(NR_VM_NODE_STAT_ITEMS);
ABI_CONSTANT(NR_VM_ZONE_STAT_ITEMS);
ABI_CONSTANT(NR_VM_EVENT_ITEMS);
ABI_CONSTANT(BIO_SEG_VALID);
ABI_CONSTANT(BIO_CLONED);
ABI_CONSTANT(BIO_BOUNCED);
ABI_CONSTANT(BIO_USER_MAPPED);
ABI_CONSTANT(BIO_NULL_MAPPED);
ABI_CONSTANT(BIO_QUIET);
ABI_CONSTANT(BIO_CHAIN);
ABI_CONSTANT(BIO_REFFED);
ABI_CONSTANT(BIO_THROTTLED);
ABI_CONSTANT(BIO_TRACE_COMPLETION);
ABI_CONSTANT(BIO_QUEUE_ENTERED);
ABI_CONSTANT(BVEC_POOL_NR);
ABI_CONSTANT(BVEC_POOL_MAX);
ABI_CONSTANT(BVEC_POOL_BITS);
ABI_CONSTANT(BVEC_POOL_OFFSET);
ABI_CONSTANT(BIO_RESET_BITS);
ABI_CONSTANT(BIO_RESET_BYTES);
ABI_VALUE(sizeof_page, sizeof(struct page));
ABI_VALUE(sizeof_bio, sizeof(struct bio));
ABI_VALUE(sizeof_zone, sizeof(struct zone));
ABI_VALUE(sizeof_pgdat, sizeof(struct pglist_data));
ABI_VALUE(sizeof_per_cpu_pageset, sizeof(struct per_cpu_pageset));
ABI_VALUE(sizeof_per_cpu_nodestat, sizeof(struct per_cpu_nodestat));
ABI_VALUE(sizeof_vm_event_state, sizeof(struct vm_event_state));

/* Force complete debug descriptions, including every enum value and alias. */
enum pageflags psi8_pageflags;
enum node_stat_item psi8_node_stat_item;
enum zone_stat_item psi8_zone_stat_item;
enum vm_event_item psi8_vm_event_item;
struct page psi8_page;
struct bio psi8_bio;
struct zone psi8_zone;
struct pglist_data psi8_pgdat;
struct per_cpu_pageset psi8_per_cpu_pageset;
struct per_cpu_nodestat psi8_per_cpu_nodestat;
struct vm_event_state psi8_vm_event_state;

typedef char psi8_bounds_must_match[(NR_PAGEFLAGS == __NR_PAGEFLAGS) ? 1 : -1];
#ifdef PSI8_CANDIDATE
ABI_CONSTANT(PG_workingset);
ABI_CONSTANT(BIO_WORKINGSET);
#include "psi8-abi-expected.h"
typedef char psi8_bio_flag_in_free_slot[(BIO_WORKINGSET == 12 &&
 BIO_WORKINGSET < BVEC_POOL_OFFSET && BIO_QUEUE_ENTERED < BIO_WORKINGSET) ? 1 : -1];
typedef char psi8_pageflag_below_metadata[(PG_workingset < LAST_CPUPID_PGOFF &&
 PG_workingset < ZONES_PGOFF && PG_workingset < NODES_PGOFF &&
 PG_workingset < SECTIONS_PGOFF) ? 1 : -1];
#endif
