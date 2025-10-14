#include <netinet/in.h>
#include <stdbool.h>

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vnet.h>
#include <vppinfra/clib.h>

#define foreach_vlan_counter		\
	_(TOTAL, total)					\
	_(PROCESSED, processed)			\
	_(DROP, drop)					\
	_(FAILED, failed)

enum
{
#define _(id, name) VLAN_##id,
	foreach_vlan_counter
#undef _
	VLAN_COUNTER_N,
};

enum
{
	NEXT_NODE_ERROR_DROP,
	NEXT_NODE_VLAN_DETUNNEL,
	NEXT_NODE_IP4,
	NEXT_NODE_IP6,
    NEXT_NODE_MPLS,
	NEXT_NODE_N,
};

typedef struct {
	u32 sw_if_index;
	u16 ethertype;
	u16 next_index;
} vlan_trace_t;

typedef struct {
	u32 counter_if_index;
	vlib_combined_counter_main_t counters[VLAN_COUNTER_N];
} vlan_detunnel_main_t;

typedef ethernet_vlan_header_t vlan_header_t;

#ifndef CLIB_MARCH_VARIANT
vlan_detunnel_main_t vlan_detunnel_main;
#else
extern vlan_detunnel_main_t vlan_detunnel_main;
#endif

static_always_inline bool process_buffer_4x(vlib_main_t *vm, vlib_buffer_t* b[4], u16 next[4])
{
	vlan_detunnel_main_t *vdm = &vlan_detunnel_main;

	u32 flags = b[0]->flags | b[1]->flags | b[2]->flags | b[3]->flags;

	if (PREDICT_FALSE(flags & VLIB_BUFFER_NEXT_PRESENT))
		return false;

	u32 sw_if_index0 = vnet_buffer(b[0])->sw_if_index[VLIB_RX];
	u32 sw_if_index1 = vnet_buffer(b[1])->sw_if_index[VLIB_RX];
	u32 sw_if_index2 = vnet_buffer(b[2])->sw_if_index[VLIB_RX];
	u32 sw_if_index3 = vnet_buffer(b[3])->sw_if_index[VLIB_RX];

	if (vdm->counter_if_index < sw_if_index0 || sw_if_index0 != sw_if_index1 || sw_if_index0 != sw_if_index2 || sw_if_index0 != sw_if_index3)
		return false;

	vlan_header_t *eth_header0 = vlib_buffer_get_current(b[0]);
	vlan_header_t *eth_header1 = vlib_buffer_get_current(b[1]);
	vlan_header_t *eth_header2 = vlib_buffer_get_current(b[2]);
	vlan_header_t *eth_header3 = vlib_buffer_get_current(b[3]);

	u16 ethertype0 = eth_header0->type;
	u16 ethertype1 = eth_header1->type;
	u16 ethertype2 = eth_header2->type;
	u16 ethertype3 = eth_header3->type;

	if (ethertype0 != ethertype1 || ethertype0 != ethertype2 || ethertype0 != ethertype3)
		return false;

	u32 total_bytes = b[0]->current_length + b[1]->current_length + b[2]->current_length + b[3]->current_length;

	vlib_increment_combined_counter(&vdm->counters[VLAN_TOTAL], vm->thread_index,
			sw_if_index0, 4, total_bytes);
	vlib_increment_combined_counter(&vdm->counters[VLAN_PROCESSED], vm->thread_index,
			sw_if_index0, 4, 4 * sizeof(vlan_header_t));

	vlib_buffer_advance(b[0], sizeof(vlan_header_t));
	vlib_buffer_advance(b[1], sizeof(vlan_header_t));
	vlib_buffer_advance(b[2], sizeof(vlan_header_t));
	vlib_buffer_advance(b[3], sizeof(vlan_header_t));

	switch (ethertype0)
	{
		case __bswap_constant_16(ETHERNET_TYPE_VLAN):
		{
			next[0] = next[1] = next[2] = next[3] = NEXT_NODE_VLAN_DETUNNEL;
			break;
		}
		case __bswap_constant_16(ETHERNET_TYPE_IP4):
		{
			next[0] = next[1] = next[2] = next[3] = NEXT_NODE_ERROR_DROP;
			break;
		}
		case __bswap_constant_16(ETHERNET_TYPE_IP6):
		{
			next[0] = next[1] = next[2] = next[3] = NEXT_NODE_ERROR_DROP;
			break;
		}
		default:
		{
			vlib_increment_combined_counter(&vdm->counters[VLAN_DROP], vm->thread_index,
					sw_if_index0, 4, total_bytes);
			next[0] = next[1] = next[2] = next[3] = NEXT_NODE_ERROR_DROP;
			break;
		}
	}

	return true;
}

static_always_inline u16 process_buffer_1x(vlib_main_t *vm, vlib_buffer_t *b, vlan_trace_t *t)
{
	vlan_detunnel_main_t *vdm = &vlan_detunnel_main;
	t->sw_if_index = vnet_buffer(b)->sw_if_index[VLIB_RX];
	t->ethertype = 0;
	t->next_index = NEXT_NODE_ERROR_DROP;

	if (PREDICT_FALSE(vdm->counter_if_index < t->sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&vdm->counters[VLAN_##id], t->sw_if_index);
	foreach_vlan_counter
#undef _

		for (u32 i = vdm->counter_if_index + 1; i <= t->sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&vdm->counters[VLAN_##id], i);
	foreach_vlan_counter
#undef _
		}

		vdm->counter_if_index = t->sw_if_index;
	}

	vlib_increment_combined_counter(&vdm->counters[VLAN_TOTAL], vm->thread_index,
			t->sw_if_index, 1, b->current_length);

	// if (b->current_length < sizeof(vlan_header_t))
	// {
	// 	vlib_increment_combined_counter(&vdm->counters[VLAN_FAILED], vm->thread_index,
	// 			t->sw_if_index, 1, sizeof(vlan_header_t));
	// 	return t->next_index;
	// }

	vlan_header_t *vlan_header = vlib_buffer_get_current(b);
	vlib_buffer_advance(b, sizeof(vlan_header_t));
	vlib_increment_combined_counter(&vdm->counters[VLAN_PROCESSED], vm->thread_index,
			t->sw_if_index, 1, sizeof(vlan_header_t));

	t->ethertype = vlan_header->type;

	switch (t->ethertype)
	{
		case ETHERNET_TYPE_VLAN:
		{
			t->next_index = NEXT_NODE_VLAN_DETUNNEL;
			break;
		}
		case ETHERNET_TYPE_IP4:
		{
			t->next_index = NEXT_NODE_ERROR_DROP;
			break;
		}
		case ETHERNET_TYPE_IP6:
		{
			t->next_index = NEXT_NODE_ERROR_DROP;
			break;
		}
		case ETHERNET_TYPE_MPLS:
		{
			t->next_index = NEXT_NODE_ERROR_DROP;
			break;
		}
		default:
		{
			vlib_increment_combined_counter(&vdm->counters[VLAN_DROP], vm->thread_index,
					t->sw_if_index, 1, b->current_length);
			t->next_index = NEXT_NODE_ERROR_DROP;
			break;
		}
	}

	return t->next_index;
}

// static_always_inline void trace_buffer(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, vlan_trace_t *t)
// {
// 	if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
// 	{
// 		vlan_trace_t *trace = vlib_add_trace(vm, node, b, sizeof(vlan_trace_t));
// 		*trace = *t;
// 	}
// }

#ifndef CLIB_MARCH_VARIANT

static u8 *format_vlan_trace(u8 *s, va_list *args)
{
	vlib_main_t *CLIB_UNUSED(vm)   = va_arg(*args, vlib_main_t *);
	vlib_node_t *CLIB_UNUSED(node) = va_arg(*args, vlib_node_t *);
	vlan_trace_t *t = va_arg(*args, vlan_trace_t *);
	return format(s, "vlan: sw_if_index %u ethertype 0x%04x next %u",
			t->sw_if_index, htons(t->ethertype), t->next_index);
}

/* Register node */
VLIB_REGISTER_NODE (vlan_detunnel) = {
	.name = "vlan-detunnel",
	.vector_size = sizeof(u32),
	.format_trace = format_vlan_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = 2,
	.next_nodes = {
		[NEXT_NODE_ERROR_DROP] = "error-drop",
		[NEXT_NODE_VLAN_DETUNNEL] = "vlan-detunnel"
	},
};

#endif

VLIB_NODE_FN (vlan_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
	u16 nexts[VLIB_FRAME_SIZE];
	vlib_buffer_t **b = bufs;
	u16 *next = nexts;

	u32 *from = vlib_frame_vector_args(frame);
	u32 n_left_from = frame->n_vectors;

	vlib_get_buffers(vm, from, bufs, n_left_from);
	vlan_trace_t t[4];

	// bool is_trace = node->flags & VLIB_NODE_FLAG_TRACE;

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

		if (!process_buffer_4x(vm, b, next))
		{
			next[0] = process_buffer_1x(vm, b[0], &t[0]);
			next[1] = process_buffer_1x(vm, b[1], &t[1]);
			next[2] = process_buffer_1x(vm, b[2], &t[2]);
			next[3] = process_buffer_1x(vm, b[3], &t[3]);
		}


		// if (PREDICT_FALSE(is_trace))
		// {
		// 	trace_buffer(vm, node, b[0], &t[0]);
		// 	trace_buffer(vm, node, b[1], &t[1]);
		// 	trace_buffer(vm, node, b[2], &t[2]);
		// 	trace_buffer(vm, node, b[3], &t[3]);
		// }
		b += 4;
		next += 4;
		n_left_from -= 4;
	}

	while (n_left_from > 0) {

		next[0] = process_buffer_1x(vm, b[0], &t[0]);

		// if (PREDICT_FALSE(is_trace))
		// 	trace_buffer(vm, node, b[0], &t[0]);

		b++;
		next++;
		n_left_from--;
	}

	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

static clib_error_t *vlan_detunnel_init(vlib_main_t *CLIB_UNUSED(vm))
{
	vlan_detunnel_main_t *vdm = &vlan_detunnel_main;
	vdm->counter_if_index = 0;

#define _(E, n)																\
	vlib_combined_counter_main_t *cm_##n = &vdm->counters[VLAN_##E];		\
	cm_##n->name = "vlan_" #n;												\
	cm_##n->stat_segment_name = "/detunnel/vlan/" #n;						\
	vlib_validate_combined_counter(cm_##n, 10);								\
	vlib_zero_combined_counter(cm_##n, 0);

	foreach_vlan_counter
#undef _

    return 0;
}

VLIB_INIT_FUNCTION (vlan_detunnel_init);
