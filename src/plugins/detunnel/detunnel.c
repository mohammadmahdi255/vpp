
#include "detunnel.h"
#include "vnet/ip/ip_packet.h"

#include <vnet/ethernet/ethernet.h>

#define foreach_ethertype	\
	_(vlan_ethertype)		\
	_(ip4_ethertype)		\
	_(ip6_ethertype)

#define foreach_ip_protocol	\
	_(tcp_protocol)			\
	_(udp_protocol)

#define foreach_next_node 	\
	_(vlan_next)			\
	_(ip4_next)				\
	_(ip6_next)				\
	_(udp_next)				\
	_(drop_next)

#ifndef CLIB_MARCH_VARIANT
#define _(name)						\
		u16x32 name##_u16x32;		\
		u16x16 name##_u16x16;		\
		u16x8 name##_u16x8;

foreach_ethertype
foreach_ip_protocol
foreach_next_node
#undef _
#else
#define _(name)							\
		extern u16x32 name##_u16x32;	\
		extern u16x16 name##_u16x16;	\
		extern u16x8 name##_u16x8;

foreach_ethertype
foreach_ip_protocol
foreach_next_node
#undef _
#endif

#define STR(x) #x
#define XSTR(x) STR(x)

CLIB_MARCH_FN (detunnel_init, clib_error_t *, vlib_main_t *CLIB_UNUSED(vm))
{
	clib_warning("size: %lu %s", SIMD_SIZE, XSTR(SIMD_TYPE));
	SIMD_VEC(vlan_ethertype) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_VLAN));
	SIMD_VEC(ip4_ethertype) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_IP4));
	SIMD_VEC(ip6_ethertype) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_IP6));

	SIMD_VEC(tcp_protocol) = SIMD_SPLAT(IP_PROTOCOL_TCP);
	SIMD_VEC(udp_protocol) = SIMD_SPLAT(IP_PROTOCOL_UDP);

	SIMD_VEC(drop_next) = SIMD_SPLAT(NEXT_NODE_ERROR_DROP);
	SIMD_VEC(vlan_next) = SIMD_SPLAT(NEXT_NODE_VLAN_DETUNNEL);
	SIMD_VEC(ip4_next) = SIMD_SPLAT(NEXT_NODE_IP4_DETUNNEL);
	SIMD_VEC(ip6_next) = SIMD_SPLAT(NEXT_NODE_IP6_DETUNNEL);

	return 0;
}

CLIB_MARCH_FN (ethertype_to_next, void, u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE ethertype_vec = SIMD_LOAD(next + i);
		SIMD_TYPE vlan_mask_vec = (ethertype_vec == SIMD_VEC(vlan_ethertype));
		SIMD_TYPE ip4_mask_vec = (ethertype_vec == SIMD_VEC(ip4_ethertype));
		SIMD_TYPE ip6_mask_vec = (ethertype_vec == SIMD_VEC(ip6_ethertype));
		SIMD_TYPE drop_mask_vec = ~(vlan_mask_vec | ip4_mask_vec | ip6_mask_vec);

		SIMD_TYPE result = (vlan_mask_vec & SIMD_VEC(vlan_next)) |
				(ip4_mask_vec & SIMD_VEC(ip4_next)) |
				(ip6_mask_vec & SIMD_VEC(ip6_next)) |
				(drop_mask_vec & SIMD_VEC(drop_next));

		SIMD_STORE(result, next + i);
	}
}

CLIB_MARCH_FN (ip_protocol_to_next, void, u16 *nexts, u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE ip_protocol_vec = SIMD_LOAD(nexts + i);
		SIMD_TYPE tcp_mask_vec = (ip_protocol_vec == SIMD_VEC(tcp_protocol));
		SIMD_TYPE udp_mask_vec = (ip_protocol_vec == SIMD_VEC(udp_protocol));
		SIMD_TYPE drop_mask = ~(tcp_mask_vec | udp_mask_vec);

		SIMD_TYPE result = (tcp_mask_vec & SIMD_VEC(drop_next)) |
				(udp_mask_vec & SIMD_VEC(drop_next)) |
				(drop_mask & SIMD_VEC(drop_next));

		SIMD_STORE(result, nexts + i);
	}
}

#ifndef CLIB_MARCH_VARIANT
void ethertype_to_next(u16 *next, u16 len)
{
	CLIB_MARCH_FN_SELECT (ethertype_to_next) (next, len);
}

void ip_protocol_to_next(u16 *nexts, u16 len)
{
	CLIB_MARCH_FN_SELECT (ip_protocol_to_next) (nexts, len);
}

u8 *format_detunnel_trace(u8 *s, va_list *args)
{
	vlib_main_t *CLIB_UNUSED(vm)   = va_arg(*args, vlib_main_t *);
	vlib_node_t *CLIB_UNUSED(node) = va_arg(*args, vlib_node_t *);
	detunnel_trace_t *t = va_arg(*args, detunnel_trace_t *);
	return format(s, "%s: if index %u next protocol 0x%04x", t->name, t->sw_if_index, t->next_protocol);
}
#endif

static_always_inline clib_error_t *detunnel_worker_init(vlib_main_t *vm)
{
	return 0;
}

static_always_inline clib_error_t *detunnel_init(vlib_main_t *vm)
{
	return CLIB_MARCH_FN_SELECT (detunnel_init) (vm);
}

VLIB_WORKER_INIT_FUNCTION (detunnel_worker_init);
VLIB_INIT_FUNCTION (detunnel_init);