
#include "detunnel.h"

#include <vnet/ethernet/ethernet.h>

#ifndef CLIB_MARCH_VARIANT
#define _(name)						\
		u16x32 name##_u16x32;		\
		u16x16 name##_u16x16;		\
		u16x8 name##_u16x8;

foreach_next_node_field
#undef _
#else
#define _(name)						\
		extern u16x32 name##_u16x32;		\
		extern u16x16 name##_u16x16;		\
		extern u16x8 name##_u16x8;

foreach_next_node_field
#undef _
#endif

#define STR(x) #x
#define XSTR(x) STR(x)

CLIB_MARCH_FN (detunnel_init, clib_error_t *, vlib_main_t *CLIB_UNUSED(vm))
{
	clib_warning("size: %lu %s", SIMD_SIZE, XSTR(SIMD_TYPE));
	SIMD_VEC(vlan_type) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_VLAN));
	SIMD_VEC(ip4_type) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_IP4));
	SIMD_VEC(ip6_type) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_IP6));

	SIMD_VEC(drop_next) = SIMD_SPLAT(NEXT_NODE_ERROR_DROP);
	SIMD_VEC(vlan_next) = SIMD_SPLAT(NEXT_NODE_VLAN_DETUNNEL);
	SIMD_VEC(ip4_next) = SIMD_SPLAT(NEXT_NODE_IP4_DETUNNEL);
	SIMD_VEC(ip6_next) = SIMD_SPLAT(NEXT_NODE_IP6_DETUNNEL);

	return 0;
}

CLIB_MARCH_FN (set_next_node, void, u16 next[VLIB_FRAME_SIZE], u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE eth_type = SIMD_LOAD(next + i);
		SIMD_TYPE vlan_mask = (eth_type == SIMD_VEC(vlan_type));
		SIMD_TYPE ip4_mask = (eth_type == SIMD_VEC(ip4_type));
		SIMD_TYPE ip6_mask = (eth_type == SIMD_VEC(ip6_type));
		SIMD_TYPE drop_mask = ~(vlan_mask | ip4_mask | ip6_mask);

		SIMD_TYPE result = (vlan_mask & SIMD_VEC(vlan_next)) |
				(ip4_mask & SIMD_VEC(ip4_next)) |
				(ip6_mask & SIMD_VEC(ip6_next)) |
				(drop_mask & SIMD_VEC(drop_next));

		SIMD_STORE(result, next + i);
	}
}

#ifndef CLIB_MARCH_VARIANT
void set_next_node(u16 next[VLIB_FRAME_SIZE], u16 len)
{
	CLIB_MARCH_FN_SELECT (set_next_node) (next, len);
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