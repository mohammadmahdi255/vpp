#ifndef DETUNNEL_H_
#define DETUNNEL_H_

#include <vlib/vlib.h>

#include <vppinfra/types.h>

#include "simd_type.h"

#define foreach_detunnel_counter	\
	_(PROCESSED, processed)

#define MAX_IF_SIZE	8
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

#define _(var)	extern simd_u16_t simd_u16(var);

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

typedef struct {
	char *name;
	u32 sw_if_index;
	u16 next_protocol;
} __clib_packed detunnel_trace_t;

#endif