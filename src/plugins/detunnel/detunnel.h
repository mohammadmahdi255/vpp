#ifndef DETUNNEL_H_
#define DETUNNEL_H_

#include <vlib/vlib.h>

#include <vppinfra/types.h>

#define foreach_detunnel_counter	\
	_(PROCESSED, processed)

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
#define ETHERNET_TYPE_INVALID	0x0000
#define IP_PROTOCOL_INVALID		0xFFFF
#define PPP_PROTOCOL_INVALID	0xFFFF

#define foreach_ethertype			\
	_(eoip_ethertype)				\
	_(vlan_ethertype)				\
	_(ipv4_ethertype)				\
	_(ipv6_ethertype)				\
	_(mpls_ethertype)				\
	_(pppoe_session_ethertype)		\
	_(pppoe_discovery_ethertype)	\
	_(ppp_ethertype)				\
	_(invalid_ethertype)

#define foreach_ip_protocol		\
	_(ipv4_protocol)			\
	_(ipv6_protocol)			\
	_(ipv6_frag_protocol)		\
	_(ipv6_route_protocol)		\
	_(ipv6_dest_protocol)		\
	_(ipv6_hop_protocol)		\
	_(ipsec_ah_protocol)		\
	_(tcp_protocol)				\
	_(udp_protocol)				\
	_(gre_protocol)				\
	_(invalid_protocol)

#undef foreach_ppp_protocol
#define foreach_ppp_protocol		\
	_(ipv4_ppp_protocol)			\
	_(ipv6_ppp_protocol)			\
	_(invalid_ppp_protocol)

#define _(var)	extern SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_ethertype
foreach_ip_protocol
foreach_ppp_protocol
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

extern u8 *format_detunnel_trace(u8 *s, va_list *args);

#endif