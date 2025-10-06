#include "vnet/ethernet/packet.h"
#include "vppinfra/clib.h"
#include <netinet/in.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>

enum
{
	VLAN,
	VLAN_FAILED,
	COUNTER_N,
};

enum
{
	NEXT_NODE_ERROR_DROP,
	NEXT_NODE_VLAN,
	NEXT_NODE_IP4,
	NEXT_NODE_IP6,
    NEXT_NODE_MPLS,
	NEXT_NODE_N,
};

typedef struct {
	u32 next_index;
	u32 sw_if_index;
	u16 ethertype;
} vlan_trace_t;

typedef struct {
	u32 counter_length;
	vlib_combined_counter_main_t counters[COUNTER_N];
} vlan_detunnel_main_t;

typedef ethernet_vlan_header_t vlan_header_t;

#ifndef CLIB_MARCH_VARIANT
vlan_detunnel_main_t vlan_detunnel_main;
#else
extern vlan_detunnel_main_t vlan_detunnel_main;
#endif


static_always_inline u16 process_packet (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b)
{
	vlan_detunnel_main_t *vdm = &vlan_detunnel_main;
	vlan_trace_t trace;
	trace.sw_if_index = vnet_buffer(b)->sw_if_index[VLIB_RX];
	trace.ethertype = 0;
	trace.next_index = NEXT_NODE_ERROR_DROP;

	if (trace.sw_if_index >= vdm->counter_length)
	{
		vlib_validate_combined_counter(&vdm->counters[VLAN], trace.sw_if_index);
		vlib_validate_combined_counter(&vdm->counters[VLAN_FAILED], trace.sw_if_index);
		for (u32 i = vdm->counter_length; i <= trace.sw_if_index; i++)
		{
			vlib_zero_combined_counter (&vdm->counters[VLAN], trace.sw_if_index);
			vlib_zero_combined_counter (&vdm->counters[VLAN_FAILED], trace.sw_if_index);
		}
		vdm->counter_length = trace.sw_if_index + 1;
	}

	if (b->current_length < sizeof(vlan_header_t))
		return NEXT_NODE_ERROR_DROP;

	vlan_header_t *vlan_header = vlib_buffer_get_current (b);
	vlib_buffer_advance(b, sizeof(vlan_header_t));
	u16 ethertype = ntohs(vlan_header->type);
	u16 next;

	switch (ethertype)
	{
		case ETHERNET_TYPE_VLAN:
			next = NEXT_NODE_VLAN;
			break;
		case ETHERNET_TYPE_IP4:
			next = NEXT_NODE_IP4;
			break;
		case ETHERNET_TYPE_IP6:
			next = NEXT_NODE_IP6;
			break;
		case ETHERNET_TYPE_MPLS:
			next = NEXT_NODE_MPLS;
			break;
		default:
			next = NEXT_NODE_ERROR_DROP;
			break;
	}

	if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	{
		vlan_trace_t *t = vlib_add_trace (vm, node, b, sizeof(vlan_trace_t));
		t->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
		t->ethertype = ethertype;
		t->next_index = next;
	}

	return next;
}

#ifndef CLIB_MARCH_VARIANT

static u8 *format_vlan_trace (u8 *s, va_list *args)
{
	vlan_trace_t *t = va_arg (*args, vlan_trace_t *);
	return format (s, "ethernet_vlan: sw_if_index %u ethertype 0x%04x next %u",
			t->sw_if_index, t->ethertype, t->next_index);
}

/* Register node */
VLIB_REGISTER_NODE (vlan_detunnel) = {
	.name = "vlan-detunnel",
	.vector_size = sizeof (u32),
	.format_trace = format_vlan_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = 1,
	.next_nodes = {
		[NEXT_NODE_ERROR_DROP] = "error-drop",
	},
};

#endif

VLIB_NODE_FN (vlan_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
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