#include <stdbool.h>

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vnet.h>
#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include "detunnel.h"
#include "vnet/ip/ip4_packet.h"
#include "vnet/ip/ip_packet.h"

enum
{
#define _(id, name) IPV4_##id,
	foreach_detunnel_counter
#undef _
	IPV4_COUNTER_N,
};

enum
{
#define _(id, name) NEXT_NODE_##id,
	foreach_detunnel_next_node
#undef _
	NEXT_NODE_N,
};

typedef struct {
	u32 sw_if_index;
	u16 ethertype;
	u16 next_index;
} ipv4_trace_t;

typedef struct {
	u32 counter_if_index;
	vlib_combined_counter_main_t counters[IPV4_COUNTER_N];
} __clib_packed ipv4_detunnel_main_t;

#ifndef CLIB_MARCH_VARIANT
ipv4_detunnel_main_t ipv4_detunnel_main;
#else
extern ipv4_detunnel_main_t ipv4_detunnel_main;
#endif

static_always_inline void add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
          u32 sw_if_index, u16 ethertype, u16 next_index)
{
	if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) && (b->flags & VLIB_BUFFER_IS_TRACED)))
	{
		ipv4_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
		t->sw_if_index = sw_if_index;
		t->ethertype = ethertype;
		t->next_index = next_index;
	}
}

static_always_inline u16 get_next_node_1x(u8 protocol)
{
	switch (protocol)
	{
		case IP_PROTOCOL_TCP:
		case IP_PROTOCOL_UDP:
		default:
			return NEXT_NODE_ERROR_DROP;
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

	next[0] = get_next_node_1x(eth0->type);
	next[1] = get_next_node_1x(eth1->type);
	next[2] = get_next_node_1x(eth2->type);
	next[3] = get_next_node_1x(eth3->type);

	// ipv4_detunnel_main_t *idm = &ipv4_detunnel_main;
	// vlib_increment_combined_counter(&idm->counters[IPV4_TOTAL],
	// 	vm->thread_index, sw_idx0, 1, len0);
	// vlib_increment_combined_counter(&idm->counters[IPV4_PROCESSED],
	// 	vm->thread_index, sw_idx0, 1, sizeof(ethernet_header_t));
	// vlib_increment_combined_counter(&idm->counters[IPV4_TOTAL],
	// 	vm->thread_index, sw_idx1, 1, len1);
	// vlib_increment_combined_counter(&idm->counters[IPV4_PROCESSED],
	// 	vm->thread_index, sw_idx1, 1, sizeof(ethernet_header_t));
	// vlib_increment_combined_counter(&idm->counters[IPV4_TOTAL],
	// 	vm->thread_index, sw_idx2, 1, len2);
	// vlib_increment_combined_counter(&idm->counters[IPV4_PROCESSED],
	// 	vm->thread_index, sw_idx2, 1, sizeof(ethernet_header_t));
	// vlib_increment_combined_counter(&idm->counters[IPV4_TOTAL],
	// 	vm->thread_index, sw_idx3, 1, len3);
	// vlib_increment_combined_counter(&idm->counters[IPV4_PROCESSED],
	// 	vm->thread_index, sw_idx3, 1, sizeof(ethernet_header_t));

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
	{
		add_trace(vm, node, b[0], sw_idx0, eth0->type, next[0]);
		add_trace(vm, node, b[1], sw_idx1, eth1->type, next[1]);
		add_trace(vm, node, b[2], sw_idx2, eth2->type, next[2]);
		add_trace(vm, node, b[3], sw_idx3, eth3->type, next[3]);
	}

	return true;
}

static_always_inline void process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next)
{
	// ipv4_detunnel_main_t *idm = &ipv4_detunnel_main;
	u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];

	// vlib_increment_combined_counter(&idm->counters[IPV4_TOTAL], vm->thread_index,
	// 		sw_idx, 1, b->current_length);

    const ip4_header_t *ip4_header = vlib_buffer_get_current(b);
    const u16 ip4_header_len = clib_max(ip4_header_bytes(ip4_header), sizeof(ip4_header_t));
    const u16 ip4_payload_len = clib_net_to_host_u16(ip4_header->length);
    const i32 ip4_padding_len = b->current_length - (ip4_header_len + ip4_payload_len);

	if (PREDICT_FALSE(ip4_payload_len < ip4_header_len || ip4_padding_len < 0))
	{
		// vlib_increment_combined_counter(&idm->counters[IPV4_FAILED], vm->thread_index,
		// 		sw_idx, 1, b->current_length);
		next[0] = NEXT_NODE_ERROR_DROP;

		if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
			add_trace(vm, node, b, sw_idx, 0, next[0]);

		return;
	}

    b->current_length -= ip4_padding_len;
	vlib_buffer_advance(b, ip4_header_len);
	// vlib_increment_combined_counter(&idm->counters[IPV4_PROCESSED], vm->thread_index,
	// 		sw_idx, 1, ip4_header_len);

	next[0] = get_next_node_1x(ip4_header->protocol);

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
		add_trace(vm, node, b, sw_idx, ip4_header->protocol, next[0]);
}

#ifndef CLIB_MARCH_VARIANT

static u8 *format_ipv4_trace(u8 *s, va_list *args)
{
	vlib_main_t *CLIB_UNUSED(vm)   = va_arg(*args, vlib_main_t *);
	vlib_node_t *CLIB_UNUSED(node) = va_arg(*args, vlib_node_t *);
	ipv4_trace_t *t = va_arg(*args, ipv4_trace_t *);
	return format(s, "ipv4: sw_if_index %u ethertype 0x%04x next %u",
			t->sw_if_index, clib_net_to_host_u16(t->ethertype), t->next_index);
}

VLIB_REGISTER_NODE (ipv4_detunnel) = {
	.name = "ipv4-detunnel",
	.vector_size = sizeof(u32),
	.format_trace = format_ipv4_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = NEXT_NODE_N,
	.next_nodes = {
#define _(id, name) [NEXT_NODE_##id] = (name),
	foreach_detunnel_next_node
#undef _
	},
};

#endif

VLIB_NODE_FN (ipv4_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
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

	ipv4_detunnel_main_t *idm = &ipv4_detunnel_main;

	if (PREDICT_FALSE(idm->counter_if_index < max_sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&idm->counters[IPV4_##id], max_sw_if_index);
	foreach_detunnel_counter
#undef _

		for (u32 i = idm->counter_if_index + 1; i <= max_sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&idm->counters[IPV4_##id], i);
	foreach_detunnel_counter
#undef _
		}

		idm->counter_if_index = max_sw_if_index;
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

		// if (!process_buffer_4x(vm, node, b, next))
		// {
			process_buffer_1x(vm, node, b[0], &next[0]);
			process_buffer_1x(vm, node, b[1], &next[1]);
			process_buffer_1x(vm, node, b[2], &next[2]);
			process_buffer_1x(vm, node, b[3], &next[3]);
		// }

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

	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

static clib_error_t *ipv4_detunnel_init(vlib_main_t *CLIB_UNUSED(vm))
{
	ipv4_detunnel_main_t *idm = &ipv4_detunnel_main;
	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	idm->counter_if_index = pool_elts(im->sw_interfaces);

#define _(E, n)																\
	vlib_combined_counter_main_t *cm_##n = &idm->counters[IPV4_##E];	\
	cm_##n->name = "ipv4_" #n;											\
	cm_##n->stat_segment_name = "/detunnel/ipv4/" #n;					\
	vlib_validate_combined_counter(cm_##n, idm->counter_if_index);			\
	vlib_zero_combined_counter(cm_##n, idm->counter_if_index);

	foreach_detunnel_counter
#undef _

	return 0;
}

VLIB_INIT_FUNCTION (ipv4_detunnel_init);