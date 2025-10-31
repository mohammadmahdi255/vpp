#include <netinet/in.h>
#include <stdbool.h>

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vnet.h>
#include <vppinfra/clib.h>

#define foreach_ethernet_counter	\
	_(TOTAL, total)					\
	_(PROCESSED, processed)			\
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
} ethernet_detunnel_main_t;

#ifndef CLIB_MARCH_VARIANT
ethernet_detunnel_main_t ethernet_detunnel_main;

#ifdef CLIB_HAVE_VEC128
u16x8 vlan_type_vec;
u16x8 ip4_type_vec;
u16x8 ip6_type_vec;
u16x8 vlan_next_vec;
u16x8 ip4_next_vec;
u16x8 ip6_next_vec;
u16x8 drop_next_vec;
#endif

#else
extern ethernet_detunnel_main_t ethernet_detunnel_main;

#ifdef CLIB_HAVE_VEC128
extern u16x8 vlan_type_vec;
extern u16x8 ip4_type_vec;
extern u16x8 ip6_type_vec;
extern u16x8 vlan_next_vec;
extern u16x8 ip4_next_vec;
extern u16x8 ip6_next_vec;
extern u16x8 drop_next_vec;
#endif

#endif

static_always_inline bool clib_u32x4_is_all_equal(const u32 *data, u32 ref)
{
#ifdef CLIB_HAVE_VEC128
	return (bool) u32x4_is_all_equal(*(u32x4u *) data, ref);
#else
    return (data[0] == ref) && (data[1] == ref) && (data[2] == ref) && (data[3] == ref);
#endif
}

/* Original switch-case approach */
static_always_inline u16 get_next_node_1x(u16 ethertype)
{
	switch (ethertype)
	{
		case __bswap_constant_16(ETHERNET_TYPE_VLAN):
			return NEXT_NODE_VLAN_DETUNNEL;
		case __bswap_constant_16(ETHERNET_TYPE_IP4):
			return NEXT_NODE_IP4;
		case __bswap_constant_16(ETHERNET_TYPE_IP6):
			return NEXT_NODE_IP6;
		default:
			return NEXT_NODE_ERROR_DROP;
	}
}

static_always_inline void get_next_node_4x(const u16 ethertype[4], u16 next[4])
{
#ifdef CLIB_HAVE_VEC128
	u16x8 eth_type_vec = u16x8_load_unaligned(ethertype);

	u16x8 vlan_mask = (eth_type_vec == vlan_type_vec);
	u16x8 ip4_mask = (eth_type_vec == ip4_type_vec);
	u16x8 ip6_mask = (eth_type_vec == ip6_type_vec);
	u16x8 drop_mask = ~(vlan_mask | ip4_mask | ip6_mask);

	u16x8 vlan_next = vlan_mask & vlan_next_vec;
	u16x8 ip4_next = ip4_mask & ip4_next_vec;
	u16x8 ip6_next = ip6_mask & ip6_next_vec;
	u16x8 drop_next = drop_mask & drop_next_vec;

	u16x8 result = vlan_next | ip4_next | ip6_next | drop_next;

	/* Store results back to array */
	u16x8_store_unaligned(result, next);
#else
	/* Fallback to optimized switch-case */
	next[0] = get_next_node_1x(ethertype[0]);
	next[1] = get_next_node_1x(ethertype[1]);
	next[2] = get_next_node_1x(ethertype[2]);
	next[3] = get_next_node_1x(ethertype[3]);
#endif
}

static_always_inline bool clib_u32x4_is_all_greater_equal(const u32 *data, u32 ref)
{
#ifdef CLIB_HAVE_VEC128
	u32x4 data_vec = u32x4_load_unaligned(data);
	u32x4 ref_vec = u32x4_splat(ref);

	u32x4 valid = data_vec >= ref_vec;
	return u32x4_is_all_equal(valid, 0xFFFFFFFF);
#else
	return (data[0] >= ref && data[1] >= ref && data[2] >= ref && data[3] >= ref);
#endif
}

static_always_inline bool clib_u32x4_sum_elts(const u32 *data)
{
#ifdef CLIB_HAVE_VEC128
	u32x4 data_vec = u32x4_load_unaligned(data);
	return u32x4_sum_elts(data_vec);
#else
	return data[0] + data[1] + data[2] + data[3];
#endif
}

static_always_inline bool process_buffer_4x(vlib_main_t *vm, vlib_node_runtime_t *node,
		vlib_buffer_t* b[4], u16 next[4])
{
	ethernet_detunnel_main_t *edm = &ethernet_detunnel_main;

	const u32 sw_idx[] = {
		vnet_buffer(b[0])->sw_if_index[VLIB_RX],
		vnet_buffer(b[1])->sw_if_index[VLIB_RX],
		vnet_buffer(b[2])->sw_if_index[VLIB_RX],
		vnet_buffer(b[3])->sw_if_index[VLIB_RX]
	};

	if (PREDICT_FALSE(edm->counter_if_index < sw_idx[0] || !clib_u32x4_is_all_equal(sw_idx, sw_idx[0])))
		return false;

	const u32 length[] = {
		b[0]->current_length,
		b[1]->current_length,
		b[2]->current_length,
		b[3]->current_length
	};

	if(PREDICT_FALSE(!clib_u32x4_is_all_greater_equal(length, sizeof(ethernet_header_t))))
		return false;

	const u16 ethertype[] = {
		((ethernet_header_t *) vlib_buffer_get_current(b[0]))->type,
		((ethernet_header_t *) vlib_buffer_get_current(b[1]))->type,
		((ethernet_header_t *) vlib_buffer_get_current(b[2]))->type,
		((ethernet_header_t *) vlib_buffer_get_current(b[3]))->type
	};

	vlib_buffer_advance(b[0], sizeof(ethernet_header_t));
	vlib_buffer_advance(b[1], sizeof(ethernet_header_t));
	vlib_buffer_advance(b[2], sizeof(ethernet_header_t));
	vlib_buffer_advance(b[3], sizeof(ethernet_header_t));

	const u32 total_bytes = clib_u32x4_sum_elts(length);

	vlib_increment_combined_counter(&edm->counters[ETHERNET_TOTAL], vm->thread_index,
			sw_idx[0], sizeof(length), total_bytes);
	vlib_increment_combined_counter(&edm->counters[ETHERNET_PROCESSED], vm->thread_index,
			sw_idx[0], 4, 4 * sizeof(ethernet_header_t));

	get_next_node_4x(ethertype, next);

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
	{
		if (PREDICT_FALSE(b[0]->flags & VLIB_BUFFER_IS_TRACED))
		{
			ethernet_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(ethernet_trace_t));
			t->sw_if_index = sw_idx[0];
			t->ethertype = ethertype[0];
			t->next_index = next[0];
		}

		if (PREDICT_FALSE(b[1]->flags & VLIB_BUFFER_IS_TRACED))
		{
			ethernet_trace_t *t = vlib_add_trace(vm, node, b[1], sizeof(ethernet_trace_t));
			t->sw_if_index = sw_idx[1];
			t->ethertype = ethertype[1];
			t->next_index = next[1];
		}

		if (PREDICT_FALSE(b[2]->flags & VLIB_BUFFER_IS_TRACED))
		{
			ethernet_trace_t *t = vlib_add_trace(vm, node, b[2], sizeof(ethernet_trace_t));
			t->sw_if_index = sw_idx[2];
			t->ethertype = ethertype[2];
			t->next_index = next[2];
		}

		if (PREDICT_FALSE(b[3]->flags & VLIB_BUFFER_IS_TRACED))
		{
			ethernet_trace_t *t = vlib_add_trace(vm, node, b[3], sizeof(ethernet_trace_t));
			t->sw_if_index = sw_idx[3];
			t->ethertype = ethertype[3];
			t->next_index = next[3];
		}
	}

	return true;
}

static_always_inline void process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next)
{
	ethernet_detunnel_main_t *edm = &ethernet_detunnel_main;
	u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];
	u16 ethertype = 0;

	if (PREDICT_FALSE(edm->counter_if_index < sw_idx))
	{
#define _(id, name) vlib_validate_combined_counter(&edm->counters[ETHERNET_##id], sw_idx);
	foreach_ethernet_counter
#undef _

		for (u32 i = edm->counter_if_index + 1; i <= sw_idx; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&edm->counters[ETHERNET_##id], i);
	foreach_ethernet_counter
#undef _
		}

		edm->counter_if_index = sw_idx;
	}

	vlib_increment_combined_counter(&edm->counters[ETHERNET_TOTAL], vm->thread_index,
			sw_idx, 1, b->current_length);

	if (PREDICT_FALSE(b->current_length < sizeof(ethernet_header_t)))
	{
		vlib_increment_combined_counter(&edm->counters[ETHERNET_FAILED], vm->thread_index,
				sw_idx, 1, b->current_length);
		next[0] = NEXT_NODE_ERROR_DROP;
	}
	else
	{
		ethertype = ((ethernet_header_t *) vlib_buffer_get_current(b))->type;
		vlib_buffer_advance(b, sizeof(ethernet_header_t));
		vlib_increment_combined_counter(&edm->counters[ETHERNET_PROCESSED], vm->thread_index,
				sw_idx, 1, sizeof(ethernet_header_t));

		next[0] = get_next_node_1x(ethertype);
	}

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
	{
		if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
		{
			ethernet_trace_t *t = vlib_add_trace(vm, node, b, sizeof(ethernet_trace_t));
			t->sw_if_index = sw_idx;
			t->ethertype = ethertype;
			t->next_index = next[0];
		}
	}
}

#ifndef CLIB_MARCH_VARIANT

static u8 *format_ethernet_trace(u8 *s, va_list *args)
{
	vlib_main_t *CLIB_UNUSED(vm)   = va_arg(*args, vlib_main_t *);
	vlib_node_t *CLIB_UNUSED(node) = va_arg(*args, vlib_node_t *);
	ethernet_trace_t *t = va_arg(*args, ethernet_trace_t *);
	return format(s, "ethernet: sw_if_index %u ethertype 0x%04x next %u",
			t->sw_if_index, ntohs(t->ethertype), t->next_index);
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

	while (n_left_from > 0) {

		process_buffer_1x(vm, node, b[0], &next[0]);

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
	vlib_validate_combined_counter(cm_##n, 10);								\
	vlib_zero_combined_counter(cm_##n, 10);

	foreach_ethernet_counter
#undef _

#ifdef CLIB_HAVE_VEC128
	vlan_type_vec = u16x8_splat(__bswap_constant_16(ETHERNET_TYPE_VLAN));
	ip4_type_vec = u16x8_splat(__bswap_constant_16(ETHERNET_TYPE_IP4));
	ip6_type_vec = u16x8_splat(__bswap_constant_16(ETHERNET_TYPE_IP6));

	vlan_next_vec = u16x8_splat(NEXT_NODE_VLAN_DETUNNEL);
	ip4_next_vec = u16x8_splat(NEXT_NODE_IP4);
	ip6_next_vec = u16x8_splat(NEXT_NODE_IP6);
	drop_next_vec = u16x8_splat(NEXT_NODE_ERROR_DROP);
#endif

	return 0;
}

VLIB_INIT_FUNCTION (ethernet_detunnel_init);

VNET_FEATURE_INIT (ethernet_detunnel_input, static) = {
	.arc_name = "device-input",
	.node_name = "ethernet-detunnel",
	.runs_before = VNET_FEATURES("ethernet-input"),
};