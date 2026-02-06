#include <vlib/vlib.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/vnet.h>

#include <vppinfra/clib.h>

#include "detunnel.h"

#define foreach_vlan_detunnel_next					\
	_(drop_next, DROP, "drop")						\
	_(vlan_next, VLAN_DETUNNEL, "vlan-detunnel")	\
	_(ipv4_next, IPV4_DETUNNEL, "ipv4-detunnel")	\
	_(ipv6_next, IPV6_DETUNNEL, "ipv6-detunnel")

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
		SIMD_TYPE ethertype_vec = SIMD_LOAD(next + i);
		SIMD_TYPE vlan_mask_vec = (ethertype_vec == SIMD_VEC(vlan_ethertype));
		SIMD_TYPE ipv4_mask_vec = (ethertype_vec == SIMD_VEC(ipv4_ethertype));
		SIMD_TYPE ipv6_mask_vec = (ethertype_vec == SIMD_VEC(ipv6_ethertype));

		SIMD_TYPE result = SIMD_VEC(drop_next) |
				(vlan_mask_vec & SIMD_VEC(vlan_next)) |
				(ipv4_mask_vec & SIMD_VEC(ipv4_next)) |
				(ipv6_mask_vec & SIMD_VEC(ipv6_next));

		SIMD_STORE(result, next + i);
	}
}

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		const vlan_header_t *vlan, const u8 is_valid)
{
	if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) && (b->flags & VLIB_BUFFER_IS_TRACED)))
	{
		vlan_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
		t->vlan = is_valid ? *vlan : (vlan_header_t){0};
	}
}

static_always_inline void
process_buffer_4x(vlib_main_t *vm, vlib_node_runtime_t *node,
		vlib_buffer_t* b[4], u16 next[4])
{
	const u32 sw_idx0 = vnet_buffer(b[0])->sw_if_index[VLIB_RX];
	const u32 sw_idx1 = vnet_buffer(b[1])->sw_if_index[VLIB_RX];
	const u32 sw_idx2 = vnet_buffer(b[2])->sw_if_index[VLIB_RX];
	const u32 sw_idx3 = vnet_buffer(b[3])->sw_if_index[VLIB_RX];

	const u8 sw_idx_eq = sw_idx0 == sw_idx1 && sw_idx2 == sw_idx3 && sw_idx0 == sw_idx2;

	const u8 is_valid0 = vlib_buffer_has_space(b[0], sizeof(vlan_header_t));
	const u8 is_valid1 = vlib_buffer_has_space(b[1], sizeof(vlan_header_t));
	const u8 is_valid2 = vlib_buffer_has_space(b[2], sizeof(vlan_header_t));
	const u8 is_valid3 = vlib_buffer_has_space(b[3], sizeof(vlan_header_t));

	const u16 bytes0 = is_valid0 ? sizeof(vlan_header_t) : 0;
	const u16 bytes1 = is_valid1 ? sizeof(vlan_header_t) : 0;
	const u16 bytes2 = is_valid2 ? sizeof(vlan_header_t) : 0;
	const u16 bytes3 = is_valid3 ? sizeof(vlan_header_t) : 0;

	const vlan_header_t *vlan0 = vlib_buffer_get_current(b[0]);
	const vlan_header_t *vlan1 = vlib_buffer_get_current(b[1]);
	const vlan_header_t *vlan2 = vlib_buffer_get_current(b[2]);
	const vlan_header_t *vlan3 = vlib_buffer_get_current(b[3]);

	vlib_buffer_advance(b[0], bytes0);
	vlib_buffer_advance(b[1], bytes1);
	vlib_buffer_advance(b[2], bytes2);
	vlib_buffer_advance(b[3], bytes3);

	next[0] = is_valid0 ? vlan0->type : VLAN_NEXT_DROP;
	next[1] = is_valid1 ? vlan1->type : VLAN_NEXT_DROP;
	next[2] = is_valid2 ? vlan2->type : VLAN_NEXT_DROP;
	next[3] = is_valid3 ? vlan3->type : VLAN_NEXT_DROP;

	vlan_detunnel_main_t *vdm = &vlan_detunnel_main;

	if (PREDICT_TRUE(sw_idx_eq))
	{
		vdm->cache_counters[sw_idx0].packets += is_valid0 + is_valid1 + is_valid2 + is_valid3;
		vdm->cache_counters[sw_idx0].bytes += bytes0 + bytes1 + bytes2 + bytes3;
	}
	else
	{
		vdm->cache_counters[sw_idx0].packets += is_valid0;
		vdm->cache_counters[sw_idx1].packets += is_valid1;
		vdm->cache_counters[sw_idx2].packets += is_valid2;
		vdm->cache_counters[sw_idx3].packets += is_valid3;
		vdm->cache_counters[sw_idx0].bytes += bytes0;
		vdm->cache_counters[sw_idx1].bytes += bytes1;
		vdm->cache_counters[sw_idx2].bytes += bytes2;
		vdm->cache_counters[sw_idx3].bytes += bytes3;
	}

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
	{
		add_trace(vm, node, b[0], vlan0, is_valid0);
		add_trace(vm, node, b[1], vlan1, is_valid1);
		add_trace(vm, node, b[2], vlan2, is_valid2);
		add_trace(vm, node, b[3], vlan3, is_valid3);
	}
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next)
{
	vlan_detunnel_main_t *vdm = &vlan_detunnel_main;
	const u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];

	const u8 is_valid = vlib_buffer_has_space(b, sizeof(vlan_header_t));
	const u16 bytes = is_valid ? sizeof(vlan_header_t) : 0;

	const vlan_header_t *vlan = vlib_buffer_get_current(b);
	vlib_buffer_advance(b, bytes);

	next[0] = is_valid ? vlan->type : VLAN_NEXT_DROP;
	vdm->cache_counters[sw_idx].packets += is_valid;
	vdm->cache_counters[sw_idx].bytes += bytes;

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
		add_trace(vm, node, b, vlan, is_valid);
}

VLIB_NODE_FN (vlan_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
	u16 nexts[VLIB_FRAME_SIZE];
	vlib_buffer_t **b = bufs;
	u16 *next = nexts;

	u32 *from = vlib_frame_vector_args(frame);
	u32 n_left_from = frame->n_vectors;

	vlib_get_buffers(vm, from, bufs, n_left_from);

	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	u32 max_sw_if_index = pool_elts(im->sw_interfaces);

	vlan_detunnel_main_t *vdm = &vlan_detunnel_main;

	if (PREDICT_FALSE(vdm->counter_if_index < max_sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&vdm->counters[VLAN_##id], max_sw_if_index);
	foreach_detunnel_counter
#undef _

		for (u32 i = vdm->counter_if_index + 1; i <= max_sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&vdm->counters[VLAN_##id], i);
	foreach_detunnel_counter
#undef _
		}

		vdm->counter_if_index = max_sw_if_index;
	}

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

		process_buffer_4x(vm, node, b, next);

		b += 4;
		next += 4;
		n_left_from -= 4;
	}

	while (n_left_from > 0)
	{
		process_buffer_1x(vm, node, b[0], next);

		b++;
		next++;
		n_left_from--;
	}

	for (u32 sw_idx = 0; sw_idx <= max_sw_if_index; sw_idx++)
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
#endif

CLIB_MARCH_FN (vlan_detunnel_init, clib_error_t *, vlib_main_t __clib_unused *vm)
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));

	SIMD_VEC(drop_next) = SIMD_SPLAT(VLAN_NEXT_DROP);
	SIMD_VEC(vlan_next) = SIMD_SPLAT(VLAN_NEXT_VLAN_DETUNNEL);
	SIMD_VEC(ipv4_next) = SIMD_SPLAT(VLAN_NEXT_IPV4_DETUNNEL);
	SIMD_VEC(ipv6_next) = SIMD_SPLAT(VLAN_NEXT_IPV6_DETUNNEL);

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
