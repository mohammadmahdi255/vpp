#include <vlib/vlib.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/vnet.h>

#include <vppinfra/clib.h>

#include "detunnel.h"

#define foreach_vlan_detunnel_next						\
	_(drop_next, DROP, "drop")							\
	_(vlan_next, VLAN_DETUNNEL, "vlan-detunnel")		\
	_(ipv4_next, IPV4_DETUNNEL, "ipv4-detunnel")		\
	_(ipv6_next, IPV6_DETUNNEL, "ipv6-detunnel")		\
	_(mpls_next, MPLS_DETUNNEL, "mpls-detunnel")		\
	_(pppoe_next, PPPOE_DETUNNEL, "pppoe-detunnel")		\
	_(ppp_next, PPP_DETUNNEL, "ppp-detunnel")			\
	_(failed_next, FAILED_DETUNNEL, "failed-detunnel")

enum
{
#define _(var, id, name) VLAN_NEXT_##id,
	foreach_vlan_detunnel_next
#undef _
	VLAN_NEXT_N,
};

#define _(var, id, name) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_vlan_detunnel_next
#undef _

enum
{
#define _(id, name) VLAN_##id,
	foreach_detunnel_counter
#undef _
	VLAN_COUNTER_N,
};

typedef ethernet_vlan_header_t vlan_header_t;

typedef struct
{
	vlan_header_t vlan;
} vlan_trace_t;

typedef struct
{
	u32 counter_if_index;
	vlib_counter_t cache_counters[MAX_IF_SIZE];
	vlib_combined_counter_main_t counters[VLAN_COUNTER_N];
} vlan_detunnel_main_t;

extern vlan_detunnel_main_t vlan_detunnel_main;

static_always_inline void
vlan_to_next(u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE next_vec = SIMD_LOAD(next + i);
		SIMD_TYPE vlan_mask_vec = (next_vec == SIMD_VEC(vlan_ethertype));
		SIMD_TYPE ipv4_mask_vec = (next_vec == SIMD_VEC(ipv4_ethertype));
		SIMD_TYPE ipv6_mask_vec = (next_vec == SIMD_VEC(ipv6_ethertype));
		SIMD_TYPE mpls_mask_vec = (next_vec == SIMD_VEC(mpls_ethertype));
		SIMD_TYPE pppoe_mask_vec = (next_vec == SIMD_VEC(pppoe_session_ethertype)) |
				(next_vec == SIMD_VEC(pppoe_discovery_ethertype));
		SIMD_TYPE ppp_mask_vec = (next_vec == SIMD_VEC(ppp_ethertype));
		SIMD_TYPE failed_mask_vec = (next_vec == SIMD_VEC(invalid_ethertype));

		SIMD_TYPE result = SIMD_VEC(drop_next) |
				(vlan_mask_vec & SIMD_VEC(vlan_next)) |
				(ipv4_mask_vec & SIMD_VEC(ipv4_next)) |
				(ipv6_mask_vec & SIMD_VEC(ipv6_next)) |
				(mpls_mask_vec & SIMD_VEC(mpls_next)) |
				(pppoe_mask_vec & SIMD_VEC(pppoe_next)) |
				(ppp_mask_vec & SIMD_VEC(ppp_next)) |
				(failed_mask_vec & SIMD_VEC(failed_next));

		SIMD_STORE(result, next + i);
	}
}

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		const vlan_header_t *vlan)
{
	if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
	{
		vlan_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
		t->vlan = *vlan;
	}
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next, u8 is_trace)
{
	vlan_detunnel_main_t *vdm = &vlan_detunnel_main;
	const u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];

	const vlan_header_t *vlan = vlib_buffer_get_current(b);

	if (PREDICT_FALSE(!vlib_buffer_has_space(b, sizeof(vlan_header_t))))
	{
		next[0] = ETHERNET_TYPE_INVALID;
		goto trace;
	}

	vlib_buffer_advance(b, sizeof(vlan_header_t));
	vdm->cache_counters[sw_idx].packets++;
	vdm->cache_counters[sw_idx].bytes += sizeof(vlan_header_t);
	next[0] = vlan->type;

trace:
	if (is_trace)
		add_trace(vm, node, b, vlan);
}

static_always_inline u64
vlan_detunnel_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_trace)
{
	vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
	u16 nexts[VLIB_FRAME_SIZE];
	vlib_buffer_t **b = bufs;
	u16 *next = nexts;

	u32 *from = vlib_frame_vector_args(frame);
	u32 n_left_from = frame->n_vectors;

	vlib_get_buffers(vm, from, bufs, n_left_from);

	vlan_detunnel_main_t *vdm = &vlan_detunnel_main;

	while (n_left_from >= 4)
	{
		if (n_left_from >= 8)
		{
			vlib_prefetch_buffer_header(b[4], LOAD);
			vlib_prefetch_buffer_header(b[5], LOAD);
			vlib_prefetch_buffer_header(b[6], LOAD);
			vlib_prefetch_buffer_header(b[7], LOAD);

			vlib_prefetch_buffer_data(b[4], LOAD);
			vlib_prefetch_buffer_data(b[5], LOAD);
			vlib_prefetch_buffer_data(b[6], LOAD);
			vlib_prefetch_buffer_data(b[7], LOAD);
		}

		process_buffer_1x(vm, node, b[0], &next[0], is_trace);
		process_buffer_1x(vm, node, b[1], &next[1], is_trace);
		process_buffer_1x(vm, node, b[2], &next[2], is_trace);
		process_buffer_1x(vm, node, b[3], &next[3], is_trace);

		b += 4;
		next += 4;
		n_left_from -= 4;
	}

	while (n_left_from > 0)
	{
		process_buffer_1x(vm, node, b[0], next, is_trace);

		b++;
		next++;
		n_left_from--;
	}

	for (u32 sw_idx = 0; sw_idx <= vdm->counter_if_index; sw_idx++)
	{
		vlib_counter_t *counter = &vdm->cache_counters[sw_idx];
		vlib_increment_combined_counter(&vdm->counters[VLAN_PROCESSED], vm->thread_index,
				sw_idx, counter->packets, counter->bytes);

		counter->packets = 0;
		counter->bytes = 0;
	}

	vlan_to_next(nexts, frame->n_vectors);
	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

VLIB_NODE_FN (vlan_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	return vlan_detunnel_inline(vm, node, frame, node->flags & VLIB_NODE_FLAG_TRACE);
}

#ifndef CLIB_MARCH_VARIANT
vlan_detunnel_main_t vlan_detunnel_main;

static u8 *format_vlan_trace(u8 *s, va_list *args)
{
	vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
	vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
	vlan_trace_t *t = va_arg(*args, vlan_trace_t *);
	return format(s, "priority_cfi_and_id   0x%04x\n"
			"  ethertype             0x%04x",
			t->vlan.priority_cfi_and_id,
			clib_net_to_host_u16(t->vlan.type));
}

/* Register node */
VLIB_REGISTER_NODE (vlan_detunnel) = {
	.name = "vlan-detunnel",
	.vector_size = sizeof(u32),
	.format_trace = format_vlan_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = VLAN_NEXT_N,
	.next_nodes = {
#define _(var, id, name) [VLAN_NEXT_##id] = (name),
	foreach_vlan_detunnel_next
#undef _
	},
};

void vlan_detunnel_counter_validate(u32 sw_if_index)
{
	vlan_detunnel_main_t *vdm = &vlan_detunnel_main;

	if (PREDICT_FALSE(vdm->counter_if_index < sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&vdm->counters[VLAN_##id], sw_if_index);
	foreach_detunnel_counter
#undef _

		for (u32 i = vdm->counter_if_index + 1; i <= sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&vdm->counters[VLAN_##id], i);
	foreach_detunnel_counter
#undef _
		}

		vdm->counter_if_index = sw_if_index;
	}
}

#endif

CLIB_MARCH_FN (vlan_detunnel_init, clib_error_t *, vlib_main_t __clib_unused *vm)
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));

	SIMD_VEC(drop_next) = SIMD_SPLAT(VLAN_NEXT_DROP);
	SIMD_VEC(vlan_next) = SIMD_SPLAT(VLAN_NEXT_VLAN_DETUNNEL);
	SIMD_VEC(ipv4_next) = SIMD_SPLAT(VLAN_NEXT_IPV4_DETUNNEL);
	SIMD_VEC(ipv6_next) = SIMD_SPLAT(VLAN_NEXT_IPV6_DETUNNEL);
	SIMD_VEC(mpls_next) = SIMD_SPLAT(VLAN_NEXT_MPLS_DETUNNEL);
	SIMD_VEC(pppoe_next) = SIMD_SPLAT(VLAN_NEXT_PPPOE_DETUNNEL);
	SIMD_VEC(ppp_next) = SIMD_SPLAT(VLAN_NEXT_PPP_DETUNNEL);
	SIMD_VEC(failed_next) = SIMD_SPLAT(VLAN_NEXT_FAILED_DETUNNEL);

	return 0;
}

static clib_error_t *vlan_detunnel_init(vlib_main_t *vm)
{
	vlan_detunnel_main_t *vdm = &vlan_detunnel_main;
	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	vdm->counter_if_index = pool_elts(im->sw_interfaces);

#define _(E, n)																\
	vlib_combined_counter_main_t *cm_##n = &vdm->counters[VLAN_##E];		\
	cm_##n->name = "vlan_" #n;												\
	cm_##n->stat_segment_name = "/detunnel/vlan/" #n;						\
	vlib_validate_combined_counter(cm_##n, vdm->counter_if_index);			\
	vlib_zero_combined_counter(cm_##n, vdm->counter_if_index);

	foreach_detunnel_counter
#undef _

	clib_memset(vdm->cache_counters, 0, sizeof(vdm->cache_counters));

	return CLIB_MARCH_FN_SELECT(vlan_detunnel_init) (vm);
}

VLIB_INIT_FUNCTION (vlan_detunnel_init);
