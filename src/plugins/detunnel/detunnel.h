#ifndef DETUNNEL_H_
#define DETUNNEL_H_

#include <vlib/vlib.h>

#include <vppinfra/types.h>

#define foreach_detunnel_counter	\
	_(TOTAL, total)					\
	_(PROCESSED, processed)			\
	_(FAILED, failed)

#define foreach_ethertype_detunnel_next	\
	_(DROP, "drop")						\
	_(VLAN_DETUNNEL, "vlan-detunnel")	\
	_(IPV4_DETUNNEL, "ipv4-detunnel")	\
	_(IPV6_DETUNNEL, "ip6-drop")			\
	_(UDP_DETUNNEL, "udp-detunnel")

#define foreach_ip_protocol_detunnel_next	\
	_(DROP, "drop")							\
	_(IPV4_DETUNNEL, "ipv4-detunnel")		\
	_(IPV6_DETUNNEL, "ip6-drop")				\
	_(UDP_DETUNNEL, "udp-detunnel")


#define foreach_transport_detunnel_next	\
	_(DROP, "drop")						\
	_(L2TP_DETUNNEL, "ip4-drop")		\
	_(GPRS_DETUNNEL, "ip6-drop")

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

#define DETUNNEL_CONCAT2(a, b) a##_##b
#define DETUNNEL_CONCAT(a, b) DETUNNEL_CONCAT2(a, b)

#define MAX_IF_SIZE	10

#define foreach_ethertype	\
	_(vlan_ethertype)		\
	_(ipv4_ethertype)		\
	_(ipv6_ethertype)

#define foreach_ip_protocol	\
	_(ipv4_protocol)		\
	_(ipv6_protocol)		\
	_(tcp_protocol)			\
	_(udp_protocol)

enum
{
#define _(id, name) ETHERTYPE_NEXT_##id,
	foreach_ethertype_detunnel_next
#undef _
	ETHERTYPE_NEXT_N,
};

enum
{
#define _(id, name) IP_PROTOCOL_NEXT_##id,
	foreach_ip_protocol_detunnel_next
#undef _
	IP_PROTOCOL_NEXT_N,
};

enum
{
#define _(id, name) TRANSPORT_NEXT_##id,
	foreach_transport_detunnel_next
#undef _
	TRANSPORT_NEXT_N,
};

#define _(var)	extern SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_ethertype
foreach_ip_protocol
#undef _

typedef struct {
    u8 proto;
    CLIB_ALIGN_MARK(pad, 4);
    u16 src_port;
    u16 dst_port;
} transport_rule_t;

enum {
	TRANSPORT_FIELD_PROTO,
	TRANSPORT_FIELD_SRC_PORT,
	TRANSPORT_FIELD_DST_PORT,
	TRANSPORT_NUM_FIELDS
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