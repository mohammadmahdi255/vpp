#include "vppinfra/types.h"

#define foreach_ethernet_detunnel_counter		\
	_(TOTAL, total)								\
	_(PROCESSED, processed)						\
	_(FAILED, failed)

#define foreach_ethernet_detunnel_next_node		\
	_(ERROR_DROP, "error-drop")					\
	_(VLAN_DETUNNEL, "vlan-detunnel")			\
	_(IP4_DETUNNEL, "ip4-drop")					\
	_(IP6_DETUNNEL, "ip6-drop")


/*
#define foreach_detunnel_protocol			\
		_ (ETHERNET, ethernet)				\
		_ (VLAN, vlan)
*/

// typedef enum {
// #define _(E, ...) DETUNNEL_##E,
// 	foreach_detunnel_protocol
// #undef _
// 	DETUNNEL_STATISTICS_N
// } detunnel_statistics_t;

// typedef struct
// {
// 	clib_thread_index_t index;
// } detunnel_worker_t;

// typedef struct
// {
// 	// vlib_combined_counter_main_t stat[DETUNNEL_STATISTICS_N];
// } detunnel_main_t;
