#include "vppinfra/types.h"

#define foreach_detunnel_counter	\
	_(TOTAL, total)					\
	_(PROCESSED, processed)			\
	_(FAILED, failed)

#define foreach_detunnel_next_node		\
	_(ERROR_DROP, "error-drop")			\
	_(VLAN_DETUNNEL, "vlan-detunnel")	\
	_(IP4_DETUNNEL, "ipv4-detunnel")	\
	_(IP6_DETUNNEL, "ip6-drop")

#define foreach_next_node_field 	\
	_(vlan_type)					\
	_(ip4_type)						\
	_(ip6_type)						\
	_(vlan_next)					\
	_(ip4_next)						\
	_(ip6_next)						\
	_(drop_next)

#if defined(CLIB_HAVE_VEC512)
#define SIMD_VEC(name)		name##_u16x32
#define SIMD_TYPE			u16x32
#define SIMD_SIZE			32
#define SIMD_SPLAT			u16x32_splat
#define SIMD_LOAD			u16x32_load_unaligned
#define SIMD_STORE			u16x32_store_unaligned
#elif defined(CLIB_HAVE_VEC256)
#define SIMD_VEC(name)		name##_u16x16
#define SIMD_TYPE			u16x16
#define SIMD_SIZE			16
#define SIMD_SPLAT			u16x16_splat
#define SIMD_LOAD			u16x16_load_unaligned
#define SIMD_STORE			u16x16_store_unaligned
#elif defined(CLIB_HAVE_VEC128)
#define SIMD_VEC(name)		name##_u16x8
#define SIMD_TYPE			u16x8
#define SIMD_SIZE			8
#define SIMD_SPLAT			u16x8_splat
#define SIMD_LOAD			u16x8_load_unaligned
#define SIMD_STORE			u16x8_store_unaligned
#endif


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
