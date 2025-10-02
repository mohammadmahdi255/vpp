#include "vppinfra/types.h"

#define foreach_detunnel_protocol			\
		_ (ETHERNET, ethernet)				\
		_ (VLAN, vlan)

typedef enum {
#define _(E, ...) DETUNNEL_##E,
	foreach_detunnel_protocol
#undef _
	DETUNNEL_STATISTICS_N
} detunnel_statistics_t;

typedef struct
{
	clib_thread_index_t index;
} detunnel_worker_t;

typedef struct
{
	// vlib_combined_counter_main_t stat[DETUNNEL_STATISTICS_N];
} detunnel_main_t;
