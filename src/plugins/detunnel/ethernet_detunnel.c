#include <netinet/in.h>
#include <stdbool.h>

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vnet.h>
#include <vppinfra/clib.h>

#define foreach_ethernet_detunnel_counter		\
	_(TOTAL, total)								\
	_(PROCESSED, processed)						\
	_(FAILED, failed)

#define foreach_ethernet_detunnel_next_node		\
	_(ERROR_DROP, "error-drop")					\
	_(VLAN_DETUNNEL, "vlan-detunnel")			\
	_(IP4_DETUNNEL, "ip4-drop")					\
	_(IP6_DETUNNEL, "ip6-drop")

enum
{
#define _(id, name) ETHERNET_##id,
	foreach_ethernet_detunnel_counter
#undef _
	ETHERNET_COUNTER_N,
};

enum
{
#define _(id, name) NEXT_NODE_##id,
	foreach_ethernet_detunnel_next_node
#undef _
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

#ifdef CLIB_HAVE_VEC128
	u16x8 vlan_type_vec;
	u16x8 ip4_type_vec;
	u16x8 ip6_type_vec;
	u16x8 vlan_next_vec;
	u16x8 ip4_next_vec;
	u16x8 ip6_next_vec;
	u16x8 drop_next_vec;
#endif

} ethernet_detunnel_main_t;

#ifndef CLIB_MARCH_VARIANT
ethernet_detunnel_main_t ethernet_detunnel_main;
#else
extern ethernet_detunnel_main_t ethernet_detunnel_main;
#endif

static_always_inline void add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
          u32 sw_if_index, u16 ethertype, u16 next_index)
{
	if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) &&
	                  (b->flags & VLIB_BUFFER_IS_TRACED))) {
		ethernet_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
		t->sw_if_index = sw_if_index;
		t->ethertype = ethertype;
		t->next_index = next_index;
	}
}

static_always_inline bool clib_u32x8_is_all_equal(const u32 data[8], u32 ref)
{
#ifdef CLIB_HAVE_VEC256
	return (bool) u32x8_is_all_equal(*(u32x8u *) data, ref);
#elif defined(CLIB_HAVE_VEC128)
	return (bool) u32x4_is_all_equal(*(u32x4u *) &data[0], ref) && u32x4_is_all_equal(*(u32x4u *) &data[4], ref);
#else
    for (int i = 0; i < 8; i++)
		if (data[i] != ref)
			return false;
	return true;
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
			return NEXT_NODE_IP4_DETUNNEL;
		case __bswap_constant_16(ETHERNET_TYPE_IP6):
			return NEXT_NODE_IP6_DETUNNEL;
		default:
			return NEXT_NODE_ERROR_DROP;
	}
}

static_always_inline void get_next_node_8x(const u16 ethertype[8], u16 next[8])
{
#ifdef CLIB_HAVE_VEC128
	ethernet_detunnel_main_t *edm = &ethernet_detunnel_main;
	u16x8 eth_type_vec = u16x8_load_unaligned(ethertype);

	u16x8 vlan_mask_vec = (eth_type_vec == edm->vlan_type_vec);
	u16x8 ip4_mask_vec = (eth_type_vec == edm->ip4_type_vec);
	u16x8 ip6_mask_vec = (eth_type_vec == edm->ip6_type_vec);
	u16x8 drop_mask_vec = ~(vlan_mask_vec | ip4_mask_vec | ip6_mask_vec);

	u16x8 result = (vlan_mask_vec & edm->vlan_next_vec) |
	               (ip4_mask_vec & edm->ip4_next_vec) |
	               (ip6_mask_vec & edm->ip6_next_vec) |
	               (drop_mask_vec & edm->drop_next_vec);

	u16x8_store_unaligned(result, next);
#else
	for (int i = 0; i < 8; i++)
		next[i] = get_next_node_1x(ethertype[i]);
#endif
}

static_always_inline bool clib_u32x8_is_all_greater_equal(const u32 *data, u32 ref)
{
#ifdef CLIB_HAVE_VEC256
	u32x8u data_vec = u32x8_load_unaligned(data);
	u32x8u ref_vec = u32x8_splat(ref);

	u32x8u valid = data_vec >= ref_vec;
	return u32x8_is_all_equal(valid, 0xFFFFFFFF);
#else
	return (data[0] >= ref && data[1] >= ref && data[2] >= ref && data[3] >= ref);
#endif
}

static_always_inline bool clib_u32x8_sum_elts(const u32 *data)
{
#ifdef CLIB_HAVE_VEC256
	u32x8u data_vec = u32x8_load_unaligned(data);
	return u32x8_sum_elts(data_vec);
#else
	return data[0] + data[1] + data[2] + data[3];
#endif
}

static_always_inline bool process_buffer_8x(vlib_main_t *vm, vlib_node_runtime_t *node,
		vlib_buffer_t* b[8], u16 next[8])
{
	ethernet_detunnel_main_t *edm = &ethernet_detunnel_main;

	const u32 sw_idx[] = {
		vnet_buffer(b[0])->sw_if_index[VLIB_RX],
		vnet_buffer(b[1])->sw_if_index[VLIB_RX],
		vnet_buffer(b[2])->sw_if_index[VLIB_RX],
		vnet_buffer(b[3])->sw_if_index[VLIB_RX],
		vnet_buffer(b[4])->sw_if_index[VLIB_RX],
		vnet_buffer(b[5])->sw_if_index[VLIB_RX],
		vnet_buffer(b[6])->sw_if_index[VLIB_RX],
		vnet_buffer(b[7])->sw_if_index[VLIB_RX]
	};

	if (PREDICT_FALSE(edm->counter_if_index < sw_idx[0] || !clib_u32x8_is_all_equal(sw_idx, sw_idx[0])))
		return false;

	const u32 length[] = {
		b[0]->current_length,
		b[1]->current_length,
		b[2]->current_length,
		b[3]->current_length,
		b[4]->current_length,
		b[5]->current_length,
		b[6]->current_length,
		b[7]->current_length
	};

	if(PREDICT_FALSE(!clib_u32x8_is_all_greater_equal(length, sizeof(ethernet_header_t))))
		return false;

	const u16 ethertype[] = {
		((ethernet_header_t *) vlib_buffer_get_current(b[0]))->type,
		((ethernet_header_t *) vlib_buffer_get_current(b[1]))->type,
		((ethernet_header_t *) vlib_buffer_get_current(b[2]))->type,
		((ethernet_header_t *) vlib_buffer_get_current(b[3]))->type,
		((ethernet_header_t *) vlib_buffer_get_current(b[4]))->type,
		((ethernet_header_t *) vlib_buffer_get_current(b[5]))->type,
		((ethernet_header_t *) vlib_buffer_get_current(b[6]))->type,
		((ethernet_header_t *) vlib_buffer_get_current(b[7]))->type,
	};

	for (int i = 0; i < 8; i++)
		vlib_buffer_advance(b[i], sizeof(ethernet_header_t));

	const u32 total_bytes = clib_u32x8_sum_elts(length);

	vlib_increment_combined_counter(&edm->counters[ETHERNET_TOTAL], vm->thread_index,
			sw_idx[0], sizeof(length), total_bytes);
	vlib_increment_combined_counter(&edm->counters[ETHERNET_PROCESSED], vm->thread_index,
			sw_idx[0], 4, 4 * sizeof(ethernet_header_t));

	get_next_node_8x(ethertype, next);

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
	{
		for (int i = 0; i < 8; i++)
			add_trace(vm, node, b[i], sw_idx[i], ethertype[i], next[i]);
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
	foreach_ethernet_detunnel_counter
#undef _

		for (u32 i = edm->counter_if_index + 1; i <= sw_idx; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&edm->counters[ETHERNET_##id], i);
	foreach_ethernet_detunnel_counter
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
		add_trace(vm, node, b, sw_idx, ethertype, next[0]);
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
#define _(id, name) [NEXT_NODE_##id] = (name),
	foreach_ethernet_detunnel_next_node
#undef _
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

	while (n_left_from >= 8) {

		if (n_left_from >= 16)
		{
			vlib_prefetch_buffer_header(b[8], LOAD);
			vlib_prefetch_buffer_header(b[9], LOAD);
			vlib_prefetch_buffer_header(b[10], LOAD);
			vlib_prefetch_buffer_header(b[11], LOAD);
			vlib_prefetch_buffer_header(b[12], LOAD);
			vlib_prefetch_buffer_header(b[13], LOAD);
			vlib_prefetch_buffer_header(b[14], LOAD);
			vlib_prefetch_buffer_header(b[15], LOAD);

			vlib_prefetch_buffer_data(b[8], LOAD);
			vlib_prefetch_buffer_data(b[9], LOAD);
			vlib_prefetch_buffer_data(b[10], LOAD);
			vlib_prefetch_buffer_data(b[11], LOAD);
			vlib_prefetch_buffer_data(b[12], LOAD);
			vlib_prefetch_buffer_data(b[13], LOAD);
			vlib_prefetch_buffer_data(b[14], LOAD);
			vlib_prefetch_buffer_data(b[15], LOAD);
		}

		if (!process_buffer_8x(vm, node, b, next))
		{
			process_buffer_1x(vm, node, b[0], &next[0]);
			process_buffer_1x(vm, node, b[1], &next[1]);
			process_buffer_1x(vm, node, b[2], &next[2]);
			process_buffer_1x(vm, node, b[3], &next[3]);
			process_buffer_1x(vm, node, b[4], &next[4]);
			process_buffer_1x(vm, node, b[5], &next[5]);
			process_buffer_1x(vm, node, b[6], &next[6]);
			process_buffer_1x(vm, node, b[7], &next[7]);
		}

		b += 8;
		next += 8;
		n_left_from -= 8;
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

	foreach_ethernet_detunnel_counter
#undef _

#ifdef CLIB_HAVE_VEC128
	edm->vlan_type_vec = u16x8_splat(__bswap_constant_16(ETHERNET_TYPE_VLAN));
	edm->ip4_type_vec = u16x8_splat(__bswap_constant_16(ETHERNET_TYPE_IP4));
	edm->ip6_type_vec = u16x8_splat(__bswap_constant_16(ETHERNET_TYPE_IP6));

	edm->vlan_next_vec = u16x8_splat(NEXT_NODE_VLAN_DETUNNEL);
	edm->ip4_next_vec = u16x8_splat(NEXT_NODE_IP4_DETUNNEL);
	edm->ip6_next_vec = u16x8_splat(NEXT_NODE_IP6_DETUNNEL);
	edm->drop_next_vec = u16x8_splat(NEXT_NODE_ERROR_DROP);
#endif

	return 0;
}

VLIB_INIT_FUNCTION (ethernet_detunnel_init);

VNET_FEATURE_INIT (ethernet_detunnel_input, static) = {
	.arc_name = "device-input",
	.node_name = "ethernet-detunnel",
	.runs_before = VNET_FEATURES("ethernet-input"),
};