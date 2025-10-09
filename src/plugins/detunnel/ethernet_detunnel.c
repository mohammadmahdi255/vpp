#include <netinet/in.h>
#include <stdbool.h>

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vnet.h>
#include <vppinfra/clib.h>

#define foreach_ethernet_counter	\
	_(TOTAL, total)					\
	_(PROCESSED, processed)			\
	_(DROP, drop)					\
	_(FAILED, failed)

enum
{
#define _(id, name) ETHERNET_##id,
	foreach_ethernet_counter
#undef _
	ETHERNET_COUNTER_N,
};

enum
{
	NEXT_NODE_ERROR_DROP,
	NEXT_NODE_VLAN_DETUNNEL,
	NEXT_NODE_IP4,
	NEXT_NODE_IP6,
	NEXT_NODE_N,
};

typedef struct {
	u32 sw_if_index;
	u16 ethertype;
	u16 next_index;
} ethernet_trace_t;

typedef struct {
	u32 counter_if_index;
	vlib_combined_counter_main_t counters[ETHERNET_COUNTER_N];
	u64 *ethertype_to_next;
} ethernet_detunnel_main_t;

#ifndef CLIB_MARCH_VARIANT
ethernet_detunnel_main_t ethernet_detunnel_main;
#else
extern ethernet_detunnel_main_t ethernet_detunnel_main;
#endif

static_always_inline u16 process_buffer(vlib_main_t *vm, vlib_buffer_t *b, ethernet_trace_t *t)
{
	ethernet_detunnel_main_t *edm = &ethernet_detunnel_main;
	t->sw_if_index = vnet_buffer(b)->sw_if_index[VLIB_RX];
	t->ethertype = 0;
	t->next_index = NEXT_NODE_ERROR_DROP;

	if (PREDICT_FALSE(b->flags & VLIB_BUFFER_NEXT_PRESENT))
		return t->next_index;

	if (PREDICT_FALSE(edm->counter_if_index < t->sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&edm->counters[ETHERNET_##id], t->sw_if_index);
	foreach_ethernet_counter
#undef _

		for (u32 i = edm->counter_if_index + 1; i <= t->sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&edm->counters[ETHERNET_##id], i);
	foreach_ethernet_counter
#undef _
		}

		edm->counter_if_index = t->sw_if_index;
	}

	// vlib_increment_combined_counter(&edm->counters[ETHERNET_TOTAL], vm->thread_index,
	// 		t->sw_if_index, 1, b->current_length);

	if (PREDICT_FALSE(b->current_length < sizeof(ethernet_header_t)))
	{
		// vlib_increment_combined_counter(&edm->counters[ETHERNET_FAILED], vm->thread_index,
		// 		t->sw_if_index, 1, b->current_length);
		return t->next_index;
	}

	ethernet_header_t *eth_header = vlib_buffer_get_current(b);
	vlib_buffer_advance(b, sizeof(ethernet_header_t));
	// vlib_increment_combined_counter(&edm->counters[ETHERNET_PROCESSED], vm->thread_index,
	// 		t->sw_if_index, 1, sizeof(ethernet_header_t));

	t->ethertype = ntohs(eth_header->type);

	u64 *p = hash_get(edm->ethertype_to_next, t->ethertype);
	if (p == NULL)
		return t->next_index;
	t->next_index = (u16)p[0];

	// switch (t->ethertype)
	// {
	// 	case ETHERNET_TYPE_VLAN:
	// 	{
	// 		t->next_index = NEXT_NODE_ERROR_DROP;
	// 		break;
	// 	}
	// 	case ETHERNET_TYPE_IP4:
	// 	{
	// 		t->next_index = NEXT_NODE_IP4;
	// 		break;
	// 	}
	// 	case ETHERNET_TYPE_IP6:
	// 	{
	// 		t->next_index = NEXT_NODE_IP6;
	// 		break;
	// 	}
	// 	default:
	// 	{
	// 		// vlib_increment_combined_counter(&edm->counters[ETHERNET_DROP], vm->thread_index,
	// 		// 		t->sw_if_index, 1, b->current_length);
	// 		t->next_index = NEXT_NODE_ERROR_DROP;
	// 		break;
	// 	}
	// }

	return t->next_index;
}

static_always_inline void trace_buffer(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, ethernet_trace_t *t)
{
	if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
	{
		ethernet_trace_t *trace = vlib_add_trace(vm, node, b, sizeof(ethernet_trace_t));
		*trace = *t;
	}
}

#ifndef CLIB_MARCH_VARIANT

static u8 *format_ethernet_trace(u8 *s, va_list *args)
{
	vlib_main_t *CLIB_UNUSED(vm)   = va_arg(*args, vlib_main_t *);
	vlib_node_t *CLIB_UNUSED(node) = va_arg(*args, vlib_node_t *);
	ethernet_trace_t *t = va_arg(*args, ethernet_trace_t *);
	return format(s, "ethernet: sw_if_index %u ethertype 0x%04x next %u",
			t->sw_if_index, t->ethertype, t->next_index);
}

VLIB_REGISTER_NODE (ethernet_detunnel) = {
	.name = "ethernet-detunnel",
	.vector_size = sizeof(u32),
	.format_trace = format_ethernet_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = NEXT_NODE_N,
	.next_nodes = {
		[NEXT_NODE_ERROR_DROP] = "error-drop",
		[NEXT_NODE_VLAN_DETUNNEL] = "vlan-detunnel",
		[NEXT_NODE_IP4] = "ip4-drop",
		[NEXT_NODE_IP6] = "ip6-drop",
	},
};

#endif

VLIB_NODE_FN (ethernet_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
	u16 nexts[VLIB_FRAME_SIZE];
	vlib_buffer_t **b = bufs;
	u16 *next = nexts;

	u32 *from = vlib_frame_vector_args(frame);
	u32 n_left_from = frame->n_vectors;

	vlib_get_buffers(vm, from, bufs, n_left_from);
	ethernet_trace_t t[4];

	bool is_trace = node->flags & VLIB_NODE_FLAG_TRACE;

	while (n_left_from >= 4) {

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

		next[0] = process_buffer(vm, b[0], &t[0]);
		next[1] = process_buffer(vm, b[1], &t[1]);
		next[2] = process_buffer(vm, b[2], &t[2]);
		next[3] = process_buffer(vm, b[3], &t[3]);

		if (PREDICT_FALSE(is_trace))
		{
			trace_buffer(vm, node, b[0], &t[0]);
			trace_buffer(vm, node, b[1], &t[1]);
			trace_buffer(vm, node, b[2], &t[2]);
			trace_buffer(vm, node, b[3], &t[3]);
		}

		b += 4;
		next += 4;
		n_left_from -= 4;
	}

	while (n_left_from > 0) {

		next[0] = process_buffer(vm, b[0], &t[0]);

		if (PREDICT_FALSE(is_trace))
			trace_buffer(vm, node, b[0], &t[0]);

		b++;
		next++;
		n_left_from--;
	}

	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

static clib_error_t *ethernet_detunnel_init(vlib_main_t *CLIB_UNUSED(vm))
{
	ethernet_detunnel_main_t *edm = &ethernet_detunnel_main;
	edm->counter_if_index = 0;

#define _(E, n)																\
	vlib_combined_counter_main_t *cm_##n = &edm->counters[ETHERNET_##E];	\
	cm_##n->name = "ethernet_" #n;											\
	cm_##n->stat_segment_name = "/detunnel/ethernet/" #n;					\
	vlib_validate_combined_counter(cm_##n, 0);								\
	vlib_zero_combined_counter(cm_##n, 0);

	foreach_ethernet_counter
#undef _

	edm->ethertype_to_next = hash_create(0, sizeof(u64));

    // Populate with ethertypes (use host byte order for keys)
    hash_set(edm->ethertype_to_next, ETHERNET_TYPE_VLAN, NEXT_NODE_VLAN_DETUNNEL);

	edm->ethertype_to_next[ETHERNET_TYPE_VLAN] = NEXT_NODE_VLAN_DETUNNEL;
	return 0;
}

VLIB_INIT_FUNCTION (ethernet_detunnel_init);

VNET_FEATURE_INIT (ethernet_detunnel_input, static) = {
	.arc_name = "device-input",
	.node_name = "ethernet-detunnel",
	.runs_before = VNET_FEATURES("ethernet-input"),
};