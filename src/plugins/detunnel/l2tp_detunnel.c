#include <vlib/vlib.h>

#include <vnet/vnet.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <vppinfra/string.h>

#include "detunnel.h"

#define foreach_l2tp_detunnel_next					    \
	_(drop_next, DROP, "drop")						    \
	_(ppp_next, PPP_DETUNNEL, "ppp-detunnel")			\
	_(failed_next, FAILED_DETUNNEL, "failed-detunnel")

enum
{
#define _(var, id, name) L2TP_NEXT_##id,
	foreach_l2tp_detunnel_next
#undef _
	L2TP_NEXT_N,
};

enum
{
#define _(id, name) L2TP_##id,
	foreach_detunnel_counter
#undef _
	L2TP_COUNTER_N,
};

#define L2TP_SUPPORTED_VERSION	2

typedef struct
{
	u8 priority:1;
	u8 offset_bit_present:1;
	u8 reserve2:1;
	u8 sequence_bit_present:1;
	u8 reserve:2;
	u8 length_bit_present:1;
	u8 type:1;

	u8 version:4;
	u8 reserve3:4;

	u16 tunnel_id;
	u16 session_id;
} l2tp_header_t;

typedef struct
{
	l2tp_header_t l2tp;
} l2tp_trace_t;

typedef struct
{
	u32 counter_if_index;
	vlib_counter_t cache_counters[MAX_IF_SIZE];
	vlib_combined_counter_main_t counters[L2TP_COUNTER_N];
} l2tp_detunnel_main_t;

extern l2tp_detunnel_main_t l2tp_detunnel_main;
extern vlib_node_registration_t l2tp_detunnel;

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		const l2tp_header_t *l2tp)
{
	if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) && (b->flags & VLIB_BUFFER_IS_TRACED)))
	{
		l2tp_trace_t *t = vlib_add_trace(vm, node, b, sizeof(l2tp_trace_t));
		t->l2tp = *l2tp;
	}
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next)
{
	l2tp_detunnel_main_t *ldm = &l2tp_detunnel_main;
	const u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];
	const void *data = vlib_buffer_get_current(b);
	const l2tp_header_t *l2tp = data;

	if (PREDICT_FALSE(!vlib_buffer_has_space(b, sizeof(l2tp_header_t)) || l2tp->version != L2TP_SUPPORTED_VERSION))
	{
		next[0] = L2TP_NEXT_FAILED_DETUNNEL;
		goto trace;
	}

	if (l2tp->type)
	{
		next[0] = L2TP_NEXT_DROP;
		goto trace;
	}

	u16 hdr_size = (u16) sizeof(l2tp_header_t)
			+ (l2tp->length_bit_present) * sizeof(u16)
			+ (l2tp->sequence_bit_present) * sizeof(u32);

	u16 offset = clib_net_to_host_u16(*(u16*)(data + hdr_size));

	hdr_size += (l2tp->offset_bit_present) * (sizeof(offset) + offset);

	vlib_buffer_advance(b, hdr_size);
	ldm->cache_counters[sw_idx].packets++;
	ldm->cache_counters[sw_idx].bytes += hdr_size;
	next[0] = L2TP_NEXT_PPP_DETUNNEL;

trace:
	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
		add_trace(vm, node, b, l2tp);
}

VLIB_NODE_FN (l2tp_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
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

	l2tp_detunnel_main_t *ldm = &l2tp_detunnel_main;

	if (PREDICT_FALSE(ldm->counter_if_index < max_sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&ldm->counters[L2TP_##id], max_sw_if_index);
	foreach_detunnel_counter
#undef _

		for (u32 i = ldm->counter_if_index + 1; i <= max_sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&ldm->counters[L2TP_##id], i);
	foreach_detunnel_counter
#undef _
		}

		ldm->counter_if_index = max_sw_if_index;
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

		process_buffer_1x(vm, node, b[0], &next[0]);
		process_buffer_1x(vm, node, b[1], &next[1]);
		process_buffer_1x(vm, node, b[2], &next[2]);
		process_buffer_1x(vm, node, b[3], &next[3]);

		b += 4;
		next += 4;
		n_left_from -= 4;
	}

	while (n_left_from > 0)
	{
		process_buffer_1x(vm, node, b[0], next);

		b++;
		next++;
		n_left_from--;
	}

	for (u32 sw_idx = 0; sw_idx <= max_sw_if_index; sw_idx++)
	{
		vlib_counter_t *counter = &ldm->cache_counters[sw_idx];
		vlib_increment_combined_counter(&ldm->counters[L2TP_PROCESSED], vm->thread_index,
				sw_idx, counter->packets, counter->bytes);

		counter->packets = 0;
		counter->bytes = 0;
	}

	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

#ifndef CLIB_MARCH_VARIANT
l2tp_detunnel_main_t l2tp_detunnel_main;

static u8 *format_l2tp_detunnel_trace(u8 *s, va_list *args)
{
	vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
	vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
	l2tp_trace_t *t = va_arg(*args, l2tp_trace_t *);
	return format(s, "version    0x%02x",
			t->l2tp.version);
}

VLIB_REGISTER_NODE (l2tp_detunnel) = {
	.name = "l2tp-detunnel",
	.vector_size = sizeof(u32),
	.format_trace = format_l2tp_detunnel_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = L2TP_NEXT_N,
	.next_nodes = {
#define _(var, id, name) [L2TP_NEXT_##id] = (name),
	foreach_l2tp_detunnel_next
#undef _
	},
};
#endif

static clib_error_t *l2tp_detunnel_init(vlib_main_t __clib_unused *vm)
{
	l2tp_detunnel_main_t *ldm = &l2tp_detunnel_main;
	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	ldm->counter_if_index = pool_elts(im->sw_interfaces);

#define _(E, n)																\
	vlib_combined_counter_main_t *cm_##n = &ldm->counters[L2TP_##E];	\
	cm_##n->name = "l2tp_" #n;											\
	cm_##n->stat_segment_name = "/detunnel/l2tp/" #n;					\
	vlib_validate_combined_counter(cm_##n, ldm->counter_if_index);			\
	vlib_zero_combined_counter(cm_##n, ldm->counter_if_index);

	foreach_detunnel_counter
#undef _

	clib_memset(ldm->cache_counters, 0, sizeof(ldm->cache_counters));

	return 0;
}

VLIB_INIT_FUNCTION (l2tp_detunnel_init);