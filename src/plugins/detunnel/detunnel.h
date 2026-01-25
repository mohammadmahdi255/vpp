#ifndef DETUNNEL_H_
#define DETUNNEL_H_

#include <vlib/vlib.h>

#include <vppinfra/types.h>

#define foreach_detunnel_counter	\
	_(TOTAL, total)					\
	_(PROCESSED, processed)			\
	_(FAILED, failed)

#define foreach_detunnel_next_node		\
	_(ERROR_DROP, "drop")			\
	_(VLAN_DETUNNEL, "vlan-detunnel")	\
	_(IP4_DETUNNEL, "ipv4-detunnel")	\
	_(IP6_DETUNNEL, "ip6-drop")

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

enum
{
#define _(id, name) NEXT_NODE_##id,
	foreach_detunnel_next_node
#undef _
	NEXT_NODE_N,
};

typedef struct {
	char *name;
	u32 sw_if_index;
	u16 next_protocol;
} __clib_packed detunnel_trace_t;

extern void CLIB_MARCH_FN_SELECT(ethertype_to_next) (u16 *next, u16 len);
extern void CLIB_MARCH_FN_SELECT (ip_protocol_to_next) (u16 *nexts, u16 len);
extern u8 *format_detunnel_trace(u8 *s, va_list *args);

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

#endif