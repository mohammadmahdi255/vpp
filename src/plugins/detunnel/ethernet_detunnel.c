#include <stdbool.h>

#include <vlib/vlib.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/vnet.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include "detunnel.h"

enum
{
#define _(id, name) ETHERNET_##id,
	foreach_detunnel_counter
#undef _
	ETHERNET_COUNTER_N,
};

typedef struct {
	u32 sw_if_index;
	u16 ethertype;
	u16 next_index;
} ethernet_trace_t;

typedef struct {
	u32 counter_if_index;
	vlib_combined_counter_main_t counters[ETHERNET_COUNTER_N];
} __clib_packed ethernet_detunnel_main_t;

extern ethernet_detunnel_main_t ethernet_detunnel_main;
extern vlib_node_registration_t ethernet_detunnel;

static_always_inline void add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
          u32 sw_if_index, u16 ethertype)
{
	if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) && (b->flags & VLIB_BUFFER_IS_TRACED)))
	{
		detunnel_trace_t *t = vlib_add_trace(vm, node, b, sizeof(detunnel_trace_t));
		t->name = ethernet_detunnel.name;
		t->sw_if_index = sw_if_index;
		t->next_protocol = clib_net_to_host_u16(ethertype);
	}
}

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

	if (PREDICT_FALSE(min_len < sizeof(ethernet_header_t)))
		return false;

	const ethernet_header_t *eth0 = vlib_buffer_get_current(b[0]);
	const ethernet_header_t *eth1 = vlib_buffer_get_current(b[1]);
	const ethernet_header_t *eth2 = vlib_buffer_get_current(b[2]);
	const ethernet_header_t *eth3 = vlib_buffer_get_current(b[3]);

	vlib_buffer_advance(b[0], sizeof(ethernet_header_t));
	vlib_buffer_advance(b[1], sizeof(ethernet_header_t));
	vlib_buffer_advance(b[2], sizeof(ethernet_header_t));
	vlib_buffer_advance(b[3], sizeof(ethernet_header_t));

	next[0] = eth0->type;
	next[1] = eth1->type;
	next[2] = eth2->type;
	next[3] = eth3->type;

	ethernet_detunnel_main_t *edm = &ethernet_detunnel_main;
	vlib_increment_combined_counter(&edm->counters[ETHERNET_TOTAL],
		vm->thread_index, sw_idx0, 1, len0);
	vlib_increment_combined_counter(&edm->counters[ETHERNET_PROCESSED],
		vm->thread_index, sw_idx0, 1, sizeof(ethernet_header_t));
	vlib_increment_combined_counter(&edm->counters[ETHERNET_TOTAL],
		vm->thread_index, sw_idx1, 1, len1);
	vlib_increment_combined_counter(&edm->counters[ETHERNET_PROCESSED],
		vm->thread_index, sw_idx1, 1, sizeof(ethernet_header_t));
	vlib_increment_combined_counter(&edm->counters[ETHERNET_TOTAL],
		vm->thread_index, sw_idx2, 1, len2);
	vlib_increment_combined_counter(&edm->counters[ETHERNET_PROCESSED],
		vm->thread_index, sw_idx2, 1, sizeof(ethernet_header_t));
	vlib_increment_combined_counter(&edm->counters[ETHERNET_TOTAL],
		vm->thread_index, sw_idx3, 1, len3);
	vlib_increment_combined_counter(&edm->counters[ETHERNET_PROCESSED],
		vm->thread_index, sw_idx3, 1, sizeof(ethernet_header_t));

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
	{
		add_trace(vm, node, b[0], sw_idx0, eth0->type);
		add_trace(vm, node, b[1], sw_idx1, eth1->type);
		add_trace(vm, node, b[2], sw_idx2, eth2->type);
		add_trace(vm, node, b[3], sw_idx3, eth3->type);
	}

	return true;
}

static_always_inline void process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next)
{
	ethernet_detunnel_main_t *edm = &ethernet_detunnel_main;
	u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];

	vlib_increment_combined_counter(&edm->counters[ETHERNET_TOTAL], vm->thread_index,
			sw_idx, 1, b->current_length);

	if (PREDICT_FALSE(b->current_length < sizeof(ethernet_header_t)))
	{
		vlib_increment_combined_counter(&edm->counters[ETHERNET_FAILED], vm->thread_index,
				sw_idx, 1, b->current_length);
		next[0] = NEXT_NODE_ERROR_DROP;

		if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
			add_trace(vm, node, b, sw_idx, 0);

		return;
	}

	const ethernet_header_t *eth = vlib_buffer_get_current(b);
	vlib_buffer_advance(b, sizeof(ethernet_header_t));
	vlib_increment_combined_counter(&edm->counters[ETHERNET_PROCESSED], vm->thread_index,
			sw_idx, 1, sizeof(ethernet_header_t));

	next[0] = eth->type;

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
		add_trace(vm, node, b, sw_idx, eth->type);
}

VLIB_NODE_FN (ethernet_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
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

	ethernet_detunnel_main_t *edm = &ethernet_detunnel_main;

	if (PREDICT_FALSE(edm->counter_if_index < max_sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&edm->counters[ETHERNET_##id], max_sw_if_index);
	foreach_detunnel_counter
#undef _

		for (u32 i = edm->counter_if_index + 1; i <= max_sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&edm->counters[ETHERNET_##id], i);
	foreach_detunnel_counter
#undef _
		}

		edm->counter_if_index = max_sw_if_index;
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
ethernet_detunnel_main_t ethernet_detunnel_main;

VLIB_REGISTER_NODE (ethernet_detunnel) = {
	.name = "ethernet-detunnel",
	.vector_size = sizeof(u32),
	.format_trace = format_detunnel_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = NEXT_NODE_N,
	.next_nodes = {
#define _(id, name) [NEXT_NODE_##id] = (name),
	foreach_detunnel_next_node
#undef _
	},
};
#endif

CLIB_MARCH_FN (ethernet_detunnel_init, clib_error_t *, vlib_main_t *CLIB_UNUSED(vm))
{
	ethernet_detunnel_main_t *edm = &ethernet_detunnel_main;
	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	edm->counter_if_index = pool_elts(im->sw_interfaces);

#define _(E, n)																\
	vlib_combined_counter_main_t *cm_##n = &edm->counters[ETHERNET_##E];	\
	cm_##n->name = "ethernet_" #n;											\
	cm_##n->stat_segment_name = "/detunnel/ethernet/" #n;					\
	vlib_validate_combined_counter(cm_##n, edm->counter_if_index);			\
	vlib_zero_combined_counter(cm_##n, edm->counter_if_index);

	foreach_detunnel_counter
#undef _

	return 0;
}

static clib_error_t *ethernet_detunnel_init(vlib_main_t *vm)
{
	return CLIB_MARCH_FN_SELECT (ethernet_detunnel_init) (vm);
}

VLIB_INIT_FUNCTION (ethernet_detunnel_init);

VNET_FEATURE_INIT (ethernet_detunnel_input, static) = {
	.arc_name = "device-input",
	.node_name = "ethernet-detunnel",
	.runs_before = VNET_FEATURES("ethernet-input"),
};