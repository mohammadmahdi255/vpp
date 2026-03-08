#include <vlib/vlib.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/vnet.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <vppinfra/string.h>

#include "detunnel.h"

#define foreach_detunnel_output_next					\
	_(drop_next, DROP, "drop")

#define IPV4_VERSION	0x0040

enum
{
#define _(var, id, name) DETUNNEL_OUTPUT_NEXT_##id,
	foreach_detunnel_output_next
#undef _
	DETUNNEL_OUTPUT_NEXT_N,
};

enum
{
#define _(id, name) DETUNNEL_OUTPUT_##id,
	foreach_detunnel_counter
#undef _
	DETUNNEL_OUTPUT_COUNTER_N,
};

typedef struct
{
	u8 v4_arc_index;
	u8 v6_arc_index;
} detunnel_output_main_t;

extern detunnel_output_main_t detunnel_output_main;
extern vlib_node_registration_t detunnel_output;

static_always_inline void
process_buffer_1x(vlib_buffer_t *b, u16 *next)
{
	detunnel_output_main_t *dom = &detunnel_output_main;
	u32 next_index = DETUNNEL_OUTPUT_NEXT_DROP;
	const u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];

	const u8 *l3_data = b->data + vnet_buffer(b)->l3_hdr_offset;
	const u16 ip_version = *l3_data & 0x00F0;
	u8 arc_index = ip_version == IPV4_VERSION ? dom->v4_arc_index : dom->v6_arc_index;

	vnet_feature_arc_start(arc_index, sw_idx, &next_index, b);
	next[0] = next_index;
}

VLIB_NODE_FN (detunnel_output) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
	u16 nexts[VLIB_FRAME_SIZE];
	vlib_buffer_t **b = bufs;
	u16 *next = nexts;

	u32 *from = vlib_frame_vector_args(frame);
	u32 n_left_from = frame->n_vectors;

	vlib_get_buffers(vm, from, bufs, n_left_from);

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

		process_buffer_1x(b[0], &next[0]);
		process_buffer_1x(b[1], &next[1]);
		process_buffer_1x(b[2], &next[2]);
		process_buffer_1x(b[3], &next[3]);

		b += 4;
		next += 4;
		n_left_from -= 4;
	}

	while (n_left_from > 0)
	{
		process_buffer_1x(b[0], next);

		b++;
		next++;
		n_left_from--;
	}

	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

#ifndef CLIB_MARCH_VARIANT
detunnel_output_main_t detunnel_output_main;

VLIB_REGISTER_NODE (detunnel_output) = {
	.name = "detunnel-output",
	.vector_size = sizeof(u32),
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = DETUNNEL_OUTPUT_NEXT_N,
	.next_nodes = {
#define _(var, id, name) [DETUNNEL_OUTPUT_NEXT_##id] = (name),
	foreach_detunnel_output_next
#undef _
	},
};

#endif

VNET_FEATURE_ARC_INIT (detunnel_v4_output_arc, static) =
{
	.arc_name = "detunnel-v4-output",
	.start_nodes = VNET_FEATURES ("detunnel-output"),
	.last_in_arc = "drop",
	.arc_index_ptr = &detunnel_output_main.v4_arc_index
};

VNET_FEATURE_ARC_INIT (detunnel_v6_output_arc, static) =
{
	.arc_name = "detunnel-v6-output",
	.start_nodes = VNET_FEATURES ("detunnel-output"),
	.last_in_arc = "drop",
	.arc_index_ptr = &detunnel_output_main.v6_arc_index
};

