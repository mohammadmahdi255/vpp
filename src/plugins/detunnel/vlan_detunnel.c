#include <netinet/in.h>
#include <stdbool.h>

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vnet.h>
#include <vppinfra/clib.h>

#include "detunnel.h"

#define foreach_vlan_detunnel_next					\
	_(drop_next, DROP, "drop")						\
	_(vlan_next, VLAN_DETUNNEL, "vlan-detunnel")	\
	_(ipv4_next, IPV4_DETUNNEL, "ipv4-detunnel")	\
	_(ipv6_next, IPV6_DETUNNEL, "ip6-drop")

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
	u32 sw_if_index;
} vlan_trace_t;

typedef struct
{
	u32 counter_if_index;
	vlib_counter_t cache_counters[MAX_IF_SIZE][VLAN_COUNTER_N];
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
		const vlan_header_t *vlan)
{
	if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) && (b->flags & VLIB_BUFFER_IS_TRACED)))
	{
		vlan_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
		t->vlan = *vlan;
		t->sw_if_index = vnet_buffer(b)->sw_if_index[VLIB_RX];
	}
}

static_always_inline bool
process_buffer_4x(vlib_main_t *vm, vlib_node_runtime_t *node,
		vlib_buffer_t* b[4], u16 next[4])
{
	const u32 sw_idx0 = vnet_buffer(b[0])->sw_if_index[VLIB_RX];
	const u32 sw_idx1 = vnet_buffer(b[1])->sw_if_index[VLIB_RX];
	const u32 sw_idx2 = vnet_buffer(b[2])->sw_if_index[VLIB_RX];
	const u32 sw_idx3 = vnet_buffer(b[3])->sw_if_index[VLIB_RX];

	const u32 len0 = b[0]->current_length;
	const u32 len1 = b[1]->current_length;
	const u32 len2 = b[2]->current_length;
	const u32 len3 = b[3]->current_length;

	u32 min_len = len0;
	min_len = clib_min(min_len, len1);
	min_len = clib_min(min_len, len2);
	min_len = clib_min(min_len, len3);

	if (PREDICT_FALSE(min_len < sizeof(vlan_header_t)))
		return false;

	vlan_header_t *vlan0 = vlib_buffer_get_current(b[0]);
	vlan_header_t *vlan1 = vlib_buffer_get_current(b[1]);
	vlan_header_t *vlan2 = vlib_buffer_get_current(b[2]);
	vlan_header_t *vlan3 = vlib_buffer_get_current(b[3]);

	vlib_buffer_advance(b[0], sizeof(vlan_header_t));
	vlib_buffer_advance(b[1], sizeof(vlan_header_t));
	vlib_buffer_advance(b[2], sizeof(vlan_header_t));
	vlib_buffer_advance(b[3], sizeof(vlan_header_t));

	next[0] = vlan0->type;
	next[1] = vlan1->type;
	next[2] = vlan2->type;
	next[3] = vlan3->type;

	vlan_detunnel_main_t *vdm = &vlan_detunnel_main;

	vdm->cache_counters[sw_idx0][VLAN_TOTAL].packets++;
	vdm->cache_counters[sw_idx0][VLAN_TOTAL].bytes += len0;
	vdm->cache_counters[sw_idx0][VLAN_PROCESSED].packets++;
	vdm->cache_counters[sw_idx0][VLAN_PROCESSED].bytes += sizeof(vlan_header_t);
	vdm->cache_counters[sw_idx1][VLAN_TOTAL].packets++;
	vdm->cache_counters[sw_idx1][VLAN_TOTAL].bytes += len1;
	vdm->cache_counters[sw_idx1][VLAN_PROCESSED].packets++;
	vdm->cache_counters[sw_idx1][VLAN_PROCESSED].bytes += sizeof(vlan_header_t);
	vdm->cache_counters[sw_idx2][VLAN_TOTAL].packets++;
	vdm->cache_counters[sw_idx2][VLAN_TOTAL].bytes += len2;
	vdm->cache_counters[sw_idx2][VLAN_PROCESSED].packets++;
	vdm->cache_counters[sw_idx2][VLAN_PROCESSED].bytes += sizeof(vlan_header_t);
	vdm->cache_counters[sw_idx3][VLAN_TOTAL].packets++;
	vdm->cache_counters[sw_idx3][VLAN_TOTAL].bytes += len3;
	vdm->cache_counters[sw_idx3][VLAN_PROCESSED].packets++;
	vdm->cache_counters[sw_idx3][VLAN_PROCESSED].bytes += sizeof(vlan_header_t);

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
	{
		add_trace(vm, node, b[0], vlan0);
		add_trace(vm, node, b[1], vlan1);
		add_trace(vm, node, b[2], vlan2);
		add_trace(vm, node, b[3], vlan3);
	}

	return true;
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next)
{
	vlan_detunnel_main_t *vdm = &vlan_detunnel_main;
	u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];

	vdm->cache_counters[sw_idx][VLAN_TOTAL].packets++;
	vdm->cache_counters[sw_idx][VLAN_TOTAL].bytes += b->current_length;


	if (PREDICT_FALSE(b->current_length < sizeof(vlan_header_t)))
	{
		vdm->cache_counters[sw_idx][VLAN_FAILED].packets++;
		vdm->cache_counters[sw_idx][VLAN_FAILED].bytes += b->current_length;
		next[0] = VLAN_NEXT_DROP;
		return;
	}

	const vlan_header_t *vlan = vlib_buffer_get_current(b);
	vlib_buffer_advance(b, sizeof(vlan_header_t));

	vdm->cache_counters[sw_idx][VLAN_PROCESSED].packets++;
	vdm->cache_counters[sw_idx][VLAN_PROCESSED].bytes += sizeof(vlan_header_t);

	next[0] = vlan->type;

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
		add_trace(vm, node, b, vlan);
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

		if (PREDICT_FALSE(!process_buffer_4x(vm, node, b, next)))
		{
			process_buffer_1x(vm, node, b[0], &next[0]);
			process_buffer_1x(vm, node, b[1], &next[1]);
			process_buffer_1x(vm, node, b[2], &next[2]);
			process_buffer_1x(vm, node, b[3], &next[3]);
		}


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

	vlan_to_next(nexts, frame->n_vectors);

	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

#ifndef CLIB_MARCH_VARIANT
vlan_detunnel_main_t vlan_detunnel_main;

static u8 *format_vlan_trace(u8 *s, va_list *args)
{
	vlib_main_t *CLIB_UNUSED(vm)   = va_arg(*args, vlib_main_t *);
	vlib_node_t *CLIB_UNUSED(node) = va_arg(*args, vlib_node_t *);
	vlan_trace_t *t = va_arg(*args, vlan_trace_t *);
	return format(s, "vlan detunnel: if index %u priority_cfi_and_id %u ethertype 0x%04x",
			t->sw_if_index, t->vlan.priority_cfi_and_id, t->vlan.type);
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

CLIB_MARCH_FN (vlan_detunnel_init, clib_error_t *, vlib_main_t *CLIB_UNUSED(vm))
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

	return CLIB_MARCH_FN_SELECT(vlan_detunnel_init) (vm);
}

VLIB_INIT_FUNCTION (vlan_detunnel_init);
