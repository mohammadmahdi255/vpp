#include <netinet/in.h>
#include <stdbool.h>

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vnet.h>
#include <vppinfra/clib.h>

#include "detunnel.h"

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
	vlib_combined_counter_main_t counters[VLAN_COUNTER_N];
} vlan_detunnel_main_t;

extern vlan_detunnel_main_t vlan_detunnel_main;

static_always_inline void add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
        const vlan_header_t *vlan)
{
	if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) && (b->flags & VLIB_BUFFER_IS_TRACED)))
	{
		vlan_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
		t->vlan = *vlan;
		t->sw_if_index = vnet_buffer(b)->sw_if_index[VLIB_RX];
	}
}

// static_always_inline u16 get_next_node_1x(u16 ethertype)
// {
// 	switch (ethertype)
// 	{
// 		case __bswap_constant_16(ETHERNET_TYPE_VLAN):
// 			return NEXT_NODE_VLAN_DETUNNEL;
// 		case __bswap_constant_16(ETHERNET_TYPE_IP4):
// 			return NEXT_NODE_IP4_DETUNNEL;
// 		case __bswap_constant_16(ETHERNET_TYPE_IP6):
// 			return NEXT_NODE_IP6_DETUNNEL;
// 		default:
// 			return NEXT_NODE_ERROR_DROP;
// 	}
// }

static_always_inline bool process_buffer_4x(vlib_main_t *vm, vlib_node_runtime_t *node,
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
	vlib_increment_combined_counter(&vdm->counters[VLAN_TOTAL],
		vm->thread_index, sw_idx0, 1, len0);
	vlib_increment_combined_counter(&vdm->counters[VLAN_PROCESSED],
		vm->thread_index, sw_idx0, 1, sizeof(vlan_header_t));
	vlib_increment_combined_counter(&vdm->counters[VLAN_TOTAL],
		vm->thread_index, sw_idx1, 1, len1);
	vlib_increment_combined_counter(&vdm->counters[VLAN_PROCESSED],
		vm->thread_index, sw_idx1, 1, sizeof(vlan_header_t));
	vlib_increment_combined_counter(&vdm->counters[VLAN_TOTAL],
		vm->thread_index, sw_idx2, 1, len2);
	vlib_increment_combined_counter(&vdm->counters[VLAN_PROCESSED],
		vm->thread_index, sw_idx2, 1, sizeof(vlan_header_t));
	vlib_increment_combined_counter(&vdm->counters[VLAN_TOTAL],
		vm->thread_index, sw_idx3, 1, len3);
	vlib_increment_combined_counter(&vdm->counters[VLAN_PROCESSED],
		vm->thread_index, sw_idx3, 1, sizeof(vlan_header_t));

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
	{
		add_trace(vm, node, b[0], vlan0);
		add_trace(vm, node, b[1], vlan1);
		add_trace(vm, node, b[2], vlan2);
		add_trace(vm, node, b[3], vlan3);
	}

	return true;
}

static_always_inline void process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next)
{
	vlan_detunnel_main_t *vdm = &vlan_detunnel_main;
	u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];

	vlib_increment_combined_counter(&vdm->counters[VLAN_TOTAL], vm->thread_index,
			sw_idx, 1, b->current_length);

	if (PREDICT_FALSE(b->current_length < sizeof(vlan_header_t)))
	{
		vlib_increment_combined_counter(&vdm->counters[VLAN_FAILED], vm->thread_index,
				sw_idx, 1, b->current_length);
		next[0] = NEXT_NODE_ERROR_DROP;
		return;
	}

	const vlan_header_t *vlan = vlib_buffer_get_current(b);
	vlib_buffer_advance(b, sizeof(vlan_header_t));
	vlib_increment_combined_counter(&vdm->counters[VLAN_PROCESSED], vm->thread_index,
			sw_idx, 1, sizeof(vlan_header_t));

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

		if (!process_buffer_4x(vm, node, b, next))
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
		process_buffer_1x(vm, node, b[0], &next[0]);

		b++;
		next++;
		n_left_from--;
	}

	ethertype_to_next(nexts, frame->n_vectors);

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
	.n_next_nodes = NEXT_NODE_N,
	.next_nodes = {
#define _(id, name) [NEXT_NODE_##id] = (name),
	foreach_detunnel_next_node
#undef _
	},
};
#endif

static clib_error_t *vlan_detunnel_init(vlib_main_t *CLIB_UNUSED(vm))
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

    return 0;
}

VLIB_INIT_FUNCTION (vlan_detunnel_init);
