#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/ip/ip_packet.h>

#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include <ppp/packet.h>

#include "detunnel.h"

#ifndef CLIB_MARCH_VARIANT
#define _(var)						\
		u16x32 var##_u16x32;		\
		u16x16 var##_u16x16;		\
		u16x8 var##_u16x8;

foreach_ethertype
foreach_ip_protocol
foreach_ppp_protocol
#undef _
#endif

CLIB_MARCH_FN (detunnel_init, clib_error_t *, vlib_main_t __clib_unused *vm)
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));
	SIMD_VEC(eoip_ethertype) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_EOIP));
	SIMD_VEC(vlan_ethertype) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_VLAN));
	SIMD_VEC(ipv4_ethertype) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_IP4));
	SIMD_VEC(ipv6_ethertype) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_IP6));
	SIMD_VEC(mpls_ethertype) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_MPLS));
	SIMD_VEC(pppoe_session_ethertype) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_PPPOE_SESSION));
	SIMD_VEC(pppoe_discovery_ethertype) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_PPPOE_DISCOVERY));
	SIMD_VEC(ppp_ethertype) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_PPP));
	SIMD_VEC(invalid_ethertype) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_INVALID));

	SIMD_VEC(ipv4_protocol) = SIMD_SPLAT(IP_PROTOCOL_IP_IN_IP);
	SIMD_VEC(ipv6_protocol) = SIMD_SPLAT(IP_PROTOCOL_IPV6);
	SIMD_VEC(ipv6_frag_protocol) = SIMD_SPLAT(IP_PROTOCOL_IPV6_FRAGMENTATION);
	SIMD_VEC(ipv6_route_protocol) = SIMD_SPLAT(IP_PROTOCOL_IPV6_ROUTE);
	SIMD_VEC(ipv6_dest_protocol) = SIMD_SPLAT(IP_PROTOCOL_IP6_DESTINATION_OPTIONS);
	SIMD_VEC(ipv6_hop_protocol) = SIMD_SPLAT(IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS);
	SIMD_VEC(ipsec_ah_protocol) = SIMD_SPLAT(IP_PROTOCOL_IPSEC_AH);
	SIMD_VEC(tcp_protocol) = SIMD_SPLAT(IP_PROTOCOL_TCP);
	SIMD_VEC(udp_protocol) = SIMD_SPLAT(IP_PROTOCOL_UDP);
	SIMD_VEC(gre_protocol) = SIMD_SPLAT(IP_PROTOCOL_GRE);
	SIMD_VEC(invalid_protocol) = SIMD_SPLAT(IP_PROTOCOL_INVALID);

	SIMD_VEC(ipv4_ppp_protocol) = SIMD_SPLAT(clib_host_to_net_u16(PPP_PROTOCOL_ip4));
	SIMD_VEC(ipv6_ppp_protocol) = SIMD_SPLAT(clib_host_to_net_u16(PPP_PROTOCOL_ip6));
	SIMD_VEC(invalid_ppp_protocol) = SIMD_SPLAT(clib_host_to_net_u16(PPP_PROTOCOL_INVALID));

	return 0;
}

#ifndef CLIB_MARCH_VARIANT

clib_error_t *
detunnel_worker_init(vlib_main_t __clib_unused *vm)
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

VNET_FEATURE_INIT (detunnel_input, static) = {
	.arc_name = "device-input",
	.node_name = "ethernet-detunnel",
	.runs_before = VNET_FEATURES("ethernet-input"),
};

#endif