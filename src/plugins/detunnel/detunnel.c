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
	// clib_warning("size: %lu %s", simd_u16_size, CLIB_STRING_MACRO(simd_u16_t));
	simd_u16(eoip_ethertype) = simd_u16_splat(clib_host_to_net_u16(ETHERNET_TYPE_EOIP));
	simd_u16(vlan_ethertype) = simd_u16_splat(clib_host_to_net_u16(ETHERNET_TYPE_VLAN));
	simd_u16(ipv4_ethertype) = simd_u16_splat(clib_host_to_net_u16(ETHERNET_TYPE_IP4));
	simd_u16(ipv6_ethertype) = simd_u16_splat(clib_host_to_net_u16(ETHERNET_TYPE_IP6));
	simd_u16(mpls_ethertype) = simd_u16_splat(clib_host_to_net_u16(ETHERNET_TYPE_MPLS));
	simd_u16(pppoe_session_ethertype) = simd_u16_splat(clib_host_to_net_u16(ETHERNET_TYPE_PPPOE_SESSION));
	simd_u16(pppoe_discovery_ethertype) = simd_u16_splat(clib_host_to_net_u16(ETHERNET_TYPE_PPPOE_DISCOVERY));
	simd_u16(ppp_ethertype) = simd_u16_splat(clib_host_to_net_u16(ETHERNET_TYPE_PPP));
	simd_u16(invalid_ethertype) = simd_u16_splat(clib_host_to_net_u16(ETHERNET_TYPE_INVALID));

	simd_u16(ipv4_protocol) = simd_u16_splat(IP_PROTOCOL_IP_IN_IP);
	simd_u16(ipv6_protocol) = simd_u16_splat(IP_PROTOCOL_IPV6);
	simd_u16(ipv6_frag_protocol) = simd_u16_splat(IP_PROTOCOL_IPV6_FRAGMENTATION);
	simd_u16(ipv6_route_protocol) = simd_u16_splat(IP_PROTOCOL_IPV6_ROUTE);
	simd_u16(ipv6_dest_protocol) = simd_u16_splat(IP_PROTOCOL_IP6_DESTINATION_OPTIONS);
	simd_u16(ipv6_hop_protocol) = simd_u16_splat(IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS);
	simd_u16(ipsec_ah_protocol) = simd_u16_splat(IP_PROTOCOL_IPSEC_AH);
	simd_u16(tcp_protocol) = simd_u16_splat(IP_PROTOCOL_TCP);
	simd_u16(udp_protocol) = simd_u16_splat(IP_PROTOCOL_UDP);
	simd_u16(gre_protocol) = simd_u16_splat(IP_PROTOCOL_GRE);
	simd_u16(invalid_protocol) = simd_u16_splat(IP_PROTOCOL_INVALID);

	simd_u16(ipv4_ppp_protocol) = simd_u16_splat(clib_host_to_net_u16(PPP_PROTOCOL_ip4));
	simd_u16(ipv6_ppp_protocol) = simd_u16_splat(clib_host_to_net_u16(PPP_PROTOCOL_ip6));
	simd_u16(invalid_ppp_protocol) = simd_u16_splat(clib_host_to_net_u16(PPP_PROTOCOL_INVALID));

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