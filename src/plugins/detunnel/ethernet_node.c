#include "vnet/ethernet/packet.h"
#include "vppinfra/clib.h"
#include <netinet/in.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>

#include "detunnel.h"

typedef enum
{
	ETHERNET_COUNTER,
	ETHERNET_COUNTER_FAILED,
	ETHERNET_COUNTER_N,
} ethenet_counter_t;

static vlib_combined_counter_main_t ethernet_counters[ETHERNET_COUNTER_N];

typedef struct {
	u32 next_index;
	u32 sw_if_index;
	u16 ethertype;
} ethenet_trace_t;

typedef enum
{
	ETHERNET_NEXT_DROP,
	ETHERNET_NEXT_VLAN,
	ETHERNET_NEXT_IP4,
	ETHERNET_NEXT_IP6,
	ETHERNET_NEXT_N,
} ethenet_next_t;

static_always_inline u16 process_packet (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b)
{
	u32 rx_if_index = vnet_buffer(b)->sw_if_index[VLIB_RX];

	if (rx_if_index >= vec_len (ethernet_counters->counters[0]))
	{
		vlib_validate_combined_counter_will_expand(&ethernet_counters[ETHERNET_COUNTER], rx_if_index);
		vlib_validate_combined_counter_will_expand(&ethernet_counters[ETHERNET_COUNTER_FAILED], rx_if_index);
	}

	if (b->current_length < sizeof(ethernet_header_t))
	{
		vlib_increment_combined_counter(&ethernet_counters[ETHERNET_COUNTER_FAILED], vm->thread_index,
				rx_if_index, 1, sizeof(ethernet_header_t));
		return ETHERNET_NEXT_DROP;
	}

	ethernet_header_t *eth_header = vlib_buffer_get_current (b);
	vlib_increment_combined_counter(&ethernet_counters[ETHERNET_COUNTER], vm->thread_index,
			rx_if_index, 1, sizeof(ethernet_header_t));

	u16 ethertype = ntohs(eth_header->type);
	u16 next;

	switch (ethertype)
	{
		case ETHERNET_TYPE_VLAN:
			next = ETHERNET_NEXT_VLAN;
			break;
		case ETHERNET_TYPE_IP4:
			next = ETHERNET_NEXT_IP4;
			break;
		case ETHERNET_TYPE_IP6:
			next = ETHERNET_NEXT_IP6;
			break;
		default:
			next = ETHERNET_NEXT_DROP;
			break;
	}

	if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	{
		ethenet_trace_t *t = vlib_add_trace (vm, node, b, sizeof(ethenet_trace_t));
		t->sw_if_index = rx_if_index;
		t->ethertype = ethertype;
		t->next_index = next;
	}

	return next;
}

#ifndef CLIB_MARCH_VARIANT

static_always_inline u8 *format_ethernet_trace (u8 *s, va_list *args)
{
	ethenet_trace_t *t = va_arg (*args, ethenet_trace_t *);
	return format (s, "ethernet: sw_if_index %u ethertype 0x%04x next %u",
			t->sw_if_index, t->ethertype, t->next_index);
}

VLIB_REGISTER_NODE (ethernet_node) = {
	.name = "ethernet-node",
	.vector_size = sizeof (u32),
	.format_trace = format_ethernet_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = 1,
	.next_nodes = {
		[ETHERNET_NEXT_DROP] = "drop",
	},
};

#endif

VLIB_NODE_FN (ethernet_node) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
	u16 nexts[VLIB_FRAME_SIZE];
	vlib_buffer_t **b = bufs;
	u16 *next = nexts;

	u32 *from = vlib_frame_vector_args (frame);
	u32 n_left_from = frame->n_vectors;

	vlib_get_buffers (vm, from, bufs, n_left_from);

	while (n_left_from >= 4) {

		if (n_left_from >= 8)
		{
			vlib_prefetch_buffer_header (b[4], LOAD);
			vlib_prefetch_buffer_header (b[5], LOAD);
			vlib_prefetch_buffer_header (b[6], LOAD);
			vlib_prefetch_buffer_header (b[7], LOAD);

			vlib_prefetch_buffer_data (b[4], LOAD);
			vlib_prefetch_buffer_data (b[5], LOAD);
			vlib_prefetch_buffer_data (b[6], LOAD);
			vlib_prefetch_buffer_data (b[7], LOAD);
		}

		next[0] = process_packet (vm, node, b[0]);
		next[1] = process_packet (vm, node, b[1]);
		next[2] = process_packet (vm, node, b[2]);
		next[3] = process_packet (vm, node, b[3]);

		b += 4;
		next += 4;
		n_left_from -= 4;
	}

	while (n_left_from > 0) {

		next[0] = process_packet (vm, node, b[0]);

		b++;
		next++;
		n_left_from--;
	}

	vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

static_always_inline clib_error_t *ethernet_init (vlib_main_t *vm)
{
	ethernet_counters[ETHERNET_COUNTER].name = "ethernet";
	ethernet_counters[ETHERNET_COUNTER].stat_segment_name = "/detunnel/ethernet";
	vlib_validate_combined_counter (&ethernet_counters[ETHERNET_COUNTER], 0);
	vlib_zero_combined_counter (&ethernet_counters[ETHERNET_COUNTER], 0);

	ethernet_counters[ETHERNET_COUNTER_FAILED].name = "ethernet_failed";
	ethernet_counters[ETHERNET_COUNTER_FAILED].stat_segment_name = "/detunnel/ethernet_failed";
	vlib_validate_combined_counter (&ethernet_counters[ETHERNET_COUNTER_FAILED], 0);
	vlib_zero_combined_counter (&ethernet_counters[ETHERNET_COUNTER_FAILED], 0);
	return 0;
}

VNET_FEATURE_INIT (ethernet_node_input, static) = {
	.arc_name = "device-input",
	.node_name = "ethernet-node",
	.runs_before = 0,
};

VLIB_INIT_FUNCTION (ethernet_init);
