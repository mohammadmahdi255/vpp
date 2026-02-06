
#include "detunnel.h"
#include "vnet/ip/ip_packet.h"
#include "vppinfra/clib.h"
#include "vppinfra/error.h"

#include <vnet/ethernet/ethernet.h>

#ifndef CLIB_MARCH_VARIANT
#define _(var)						\
		u16x32 var##_u16x32;		\
		u16x16 var##_u16x16;		\
		u16x8 var##_u16x8;

foreach_ethertype
foreach_ip_protocol
#undef _
#endif

CLIB_MARCH_FN (detunnel_init, clib_error_t *, vlib_main_t *CLIB_UNUSED(vm))
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));
	SIMD_VEC(vlan_ethertype) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_VLAN));
	SIMD_VEC(ipv4_ethertype) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_IP4));
	SIMD_VEC(ipv6_ethertype) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_IP6));

	SIMD_VEC(ipv4_protocol) = SIMD_SPLAT(IP_PROTOCOL_IP_IN_IP);
	SIMD_VEC(ipv6_protocol) = SIMD_SPLAT(IP_PROTOCOL_IPV6);
	SIMD_VEC(ipv6_frag_protocol) = SIMD_SPLAT(IP_PROTOCOL_IPV6_FRAGMENTATION);
	SIMD_VEC(ipv6_route_protocol) = SIMD_SPLAT(IP_PROTOCOL_IPV6_ROUTE);
	SIMD_VEC(ipv6_dest_protocol) = SIMD_SPLAT(IP_PROTOCOL_IP6_DESTINATION_OPTIONS);
	SIMD_VEC(ipv6_hop_protocol) = SIMD_SPLAT(IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS);
	SIMD_VEC(ipsec_ah_protocol) = SIMD_SPLAT(IP_PROTOCOL_IPSEC_AH);
	SIMD_VEC(tcp_protocol) = SIMD_SPLAT(IP_PROTOCOL_TCP);
	SIMD_VEC(udp_protocol) = SIMD_SPLAT(IP_PROTOCOL_UDP);

	return 0;
}

CLIB_MARCH_FN (ethertype_to_next, void, u16 *next, u16 len)
{
// 	for (u16 i = 0; i < len; i += SIMD_SIZE)
// 	{
// 		SIMD_TYPE ethertype_vec = SIMD_LOAD(next + i);
// 		SIMD_TYPE vlan_mask_vec = (ethertype_vec == SIMD_VEC(vlan_ethertype));
// 		SIMD_TYPE ip4_mask_vec = (ethertype_vec == SIMD_VEC(ip4_ethertype));
// 		SIMD_TYPE ip6_mask_vec = (ethertype_vec == SIMD_VEC(ip6_ethertype));
// 		SIMD_TYPE drop_mask_vec = ~(vlan_mask_vec | ip4_mask_vec | ip6_mask_vec);

// 		SIMD_TYPE result = (vlan_mask_vec & SIMD_VEC(vlan_next)) |
// 				(ip4_mask_vec & SIMD_VEC(ip4_next)) |
// 				(ip6_mask_vec & SIMD_VEC(ip6_next)) |
// 				(drop_mask_vec & SIMD_VEC(drop_next));

// 		SIMD_STORE(result, next + i);
// 	}
}

CLIB_MARCH_FN (ip_protocol_to_next, void, u16 *nexts, u16 len)
{
	// for (u16 i = 0; i < len; i += SIMD_SIZE)
	// {
	// 	SIMD_TYPE ip_protocol_vec = SIMD_LOAD(nexts + i);
	// 	SIMD_TYPE tcp_mask_vec = (ip_protocol_vec == SIMD_VEC(tcp_protocol));
	// 	SIMD_TYPE udp_mask_vec = (ip_protocol_vec == SIMD_VEC(udp_protocol));
	// 	SIMD_TYPE drop_mask = ~(tcp_mask_vec | udp_mask_vec);

	// 	SIMD_TYPE result = (tcp_mask_vec & SIMD_VEC(drop_next)) |
	// 			(udp_mask_vec & SIMD_VEC(udp_next)) |
	// 			(drop_mask & SIMD_VEC(drop_next));

	// 	SIMD_STORE(result, nexts + i);
	// }
}

#ifndef CLIB_MARCH_VARIANT
u8 *format_detunnel_trace(u8 *s, va_list *args)
{
	vlib_main_t *CLIB_UNUSED(vm)   = va_arg(*args, vlib_main_t *);
	vlib_node_t *CLIB_UNUSED(node) = va_arg(*args, vlib_node_t *);
	detunnel_trace_t *t = va_arg(*args, detunnel_trace_t *);
	return format(s, "%s: if index %u next protocol 0x%04x", t->name, t->sw_if_index, t->next_protocol);
}

clib_error_t *
detunnel_worker_init(vlib_main_t *CLIB_UNUSED(vm))
{
	return 0;
}

clib_error_t *
detunnel_init(vlib_main_t *vm)
{
	return CLIB_MARCH_FN_SELECT (detunnel_init) (vm);
}

VLIB_WORKER_INIT_FUNCTION (detunnel_worker_init);

VLIB_INIT_FUNCTION (detunnel_init);

#endif