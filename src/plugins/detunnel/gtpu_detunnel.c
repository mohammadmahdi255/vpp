#include <stdbool.h>

#include <vlib/vlib.h>

#include <vnet/ip/ip4_packet.h>
#include <vnet/vnet.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include <gtpu/gtpu.h>

#include "detunnel.h"

#define foreach_gtpu_detunnel_next					\
	_(drop_next, DROP, "drop")						\
	_(ipv4_next, IPV4_DETUNNEL, "ipv4-detunnel")	\
	_(ipv6_next, IPV6_DETUNNEL, "ip6-drop")

#define foreach_gtpu_protocol	\
	_(ipv4_version)				\
	_(ipv6_version)

#define IPV4_VERSION	0x0040
#define IPV6_VERSION	0x0060

enum
{
#define _(var, id, name) GTPU_NEXT_##id,
	foreach_gtpu_detunnel_next
#undef _
	GTPU_NEXT_N,
};

#define _(var, id, name) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_gtpu_detunnel_next
#undef _

#define _(var) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_gtpu_protocol
#undef _

enum
{
#define _(id, name) GTPU_##id,
	foreach_detunnel_counter
#undef _
	GTPU_COUNTER_N,
};

typedef struct
{
	gtpu_header_t gtpu;
	u32 sw_if_index;
} gtpu_trace_t;

typedef struct {
	u32 counter_if_index;
	vlib_combined_counter_main_t counters[GTPU_COUNTER_N];
} gtpu_detunnel_main_t;

extern gtpu_detunnel_main_t gtpu_detunnel_main;
extern vlib_node_registration_t gtpu_detunnel;

static_always_inline void
gtpu_to_next(u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE ip_protocol_vec = SIMD_LOAD(next + i);
		SIMD_TYPE ipv4_mask_vec = (ip_protocol_vec == SIMD_VEC(ipv4_version));
		SIMD_TYPE ipv6_mask_vec = (ip_protocol_vec == SIMD_VEC(ipv6_version));

		SIMD_TYPE result = SIMD_VEC(drop_next) |
				(ipv4_mask_vec & SIMD_VEC(ipv4_next)) |
				(ipv6_mask_vec & SIMD_VEC(ipv6_next));

		SIMD_STORE(result, next + i);
	}
}

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		const gtpu_header_t *gtpu)
{
	if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) && (b->flags & VLIB_BUFFER_IS_TRACED)))
	{
		gtpu_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
		t->gtpu = *gtpu;
		t->sw_if_index = vnet_buffer(b)->sw_if_index[VLIB_RX];
	}
}

static_always_inline bool
process_buffer_4x(vlib_main_t *vm, vlib_node_runtime_t *node,
		vlib_buffer_t* b[4], u16 next[4])
{
	gtpu_detunnel_main_t *idm = &gtpu_detunnel_main;

	const u32 sw_idx0 = vnet_buffer(b[0])->sw_if_index[VLIB_RX];
	const u32 sw_idx1 = vnet_buffer(b[1])->sw_if_index[VLIB_RX];
	const u32 sw_idx2 = vnet_buffer(b[2])->sw_if_index[VLIB_RX];
	const u32 sw_idx3 = vnet_buffer(b[3])->sw_if_index[VLIB_RX];

	const gtpu_header_t *gtpu0 = vlib_buffer_get_current(b[0]);
	const gtpu_header_t *gtpu1 = vlib_buffer_get_current(b[1]);
	const gtpu_header_t *gtpu2 = vlib_buffer_get_current(b[2]);
	const gtpu_header_t *gtpu3 = vlib_buffer_get_current(b[3]);

	const u16 gtpu_hdr_len0 = sizeof (gtpu_header_t) - (((gtpu0->ver_flags & GTPU_E_S_PN_BIT) == 0) * sizeof(u32));
	const u16 gtpu_hdr_len1 = sizeof (gtpu_header_t) - (((gtpu1->ver_flags & GTPU_E_S_PN_BIT) == 0) * sizeof(u32));
	const u16 gtpu_hdr_len2 = sizeof (gtpu_header_t) - (((gtpu2->ver_flags & GTPU_E_S_PN_BIT) == 0) * sizeof(u32));
	const u16 gtpu_hdr_len3 = sizeof (gtpu_header_t) - (((gtpu3->ver_flags & GTPU_E_S_PN_BIT) == 0) * sizeof(u32));

	u8 error = 0;

	error |= b[0]->current_length < gtpu_hdr_len0;
	error |= b[1]->current_length < gtpu_hdr_len1;
	error |= b[2]->current_length < gtpu_hdr_len2;
	error |= b[3]->current_length < gtpu_hdr_len3;

	if (PREDICT_FALSE(error))
		return false;

	vlib_buffer_advance(b[0], gtpu_hdr_len0);
	vlib_buffer_advance(b[1], gtpu_hdr_len1);
	vlib_buffer_advance(b[2], gtpu_hdr_len2);
	vlib_buffer_advance(b[3], gtpu_hdr_len3);

	next[0] = *(u8 *) vlib_buffer_get_current(b[0]) & 0xF0;
	next[1] = *(u8 *) vlib_buffer_get_current(b[1]) & 0xF0;
	next[2] = *(u8 *) vlib_buffer_get_current(b[2]) & 0xF0;
	next[3] = *(u8 *) vlib_buffer_get_current(b[3]) & 0xF0;

	vlib_increment_combined_counter(&idm->counters[GTPU_TOTAL],
		vm->thread_index, sw_idx0, 1, gtpu_hdr_len0);
	vlib_increment_combined_counter(&idm->counters[GTPU_PROCESSED],
		vm->thread_index, sw_idx0, 1, gtpu_hdr_len0);
	vlib_increment_combined_counter(&idm->counters[GTPU_TOTAL],
		vm->thread_index, sw_idx1, 1, gtpu_hdr_len1);
	vlib_increment_combined_counter(&idm->counters[GTPU_PROCESSED],
		vm->thread_index, sw_idx1, 1, gtpu_hdr_len1);
	vlib_increment_combined_counter(&idm->counters[GTPU_TOTAL],
		vm->thread_index, sw_idx2, 1, gtpu_hdr_len2);
	vlib_increment_combined_counter(&idm->counters[GTPU_PROCESSED],
		vm->thread_index, sw_idx2, 1, gtpu_hdr_len2);
	vlib_increment_combined_counter(&idm->counters[GTPU_TOTAL],
		vm->thread_index, sw_idx3, 1, gtpu_hdr_len3);
	vlib_increment_combined_counter(&idm->counters[GTPU_PROCESSED],
		vm->thread_index, sw_idx3, 1, gtpu_hdr_len3);

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
	{
		add_trace(vm, node, b[0], gtpu0);
		add_trace(vm, node, b[1], gtpu1);
		add_trace(vm, node, b[2], gtpu2);
		add_trace(vm, node, b[3], gtpu3);
	}

	return true;
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next)
{
	gtpu_detunnel_main_t *idm = &gtpu_detunnel_main;
	u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];

	vlib_increment_combined_counter(&idm->counters[GTPU_TOTAL], vm->thread_index,
			sw_idx, 1, b->current_length);

	const gtpu_header_t *gtpu = vlib_buffer_get_current(b);

	const u16 gtpu_hdr_len = sizeof (gtpu_header_t) - (((gtpu->ver_flags & GTPU_E_S_PN_BIT) == 0) * sizeof(u32));

	if (PREDICT_FALSE(b->current_length < gtpu_hdr_len))
	{
		vlib_increment_combined_counter(&idm->counters[GTPU_FAILED], vm->thread_index,
				sw_idx, 1, b->current_length);
		next[0] = GTPU_NEXT_DROP;
		return;
	}

	vlib_buffer_advance(b, gtpu_hdr_len);
	vlib_increment_combined_counter(&idm->counters[GTPU_PROCESSED], vm->thread_index,
			sw_idx, 1, gtpu_hdr_len);

	if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
		add_trace(vm, node, b, gtpu);

	next[0] = *(u8 *) vlib_buffer_get_current(b) & 0xF0;
}

VLIB_NODE_FN (gtpu_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
	u16 nexts[VLIB_FRAME_SIZE];
	u16 *next = nexts;

	vlib_buffer_t **b = bufs;

	u32 *from = vlib_frame_vector_args(frame);
	u32 n_left_from = frame->n_vectors;

	vlib_get_buffers(vm, from, bufs, n_left_from);

	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	u32 max_sw_if_index = pool_elts(im->sw_interfaces);

	gtpu_detunnel_main_t *idm = &gtpu_detunnel_main;

	if (PREDICT_FALSE(idm->counter_if_index < max_sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&idm->counters[GTPU_##id], max_sw_if_index);
	foreach_detunnel_counter
#undef _

		for (u32 i = idm->counter_if_index + 1; i <= max_sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&idm->counters[GTPU_##id], i);
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

		if (PREDICT_FALSE(!process_buffer_4x(vm, node, b, next)))
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

	gtpu_to_next(nexts, frame->n_vectors);
	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

#ifndef CLIB_MARCH_VARIANT
gtpu_detunnel_main_t gtpu_detunnel_main;

static u8 *format_gtpu_trace(u8 *s, va_list *args)
{
	vlib_main_t *CLIB_UNUSED(vm)   = va_arg(*args, vlib_main_t *);
	vlib_node_t *CLIB_UNUSED(node) = va_arg(*args, vlib_node_t *);
	gtpu_trace_t *t = va_arg(*args, gtpu_trace_t *);
	return format(s, "gtpu detunnel: if index %u ver_flags %u",
			t->sw_if_index, t->gtpu.ver_flags);
}

VLIB_REGISTER_NODE (gtpu_detunnel) = {
	.name = "gtpu-detunnel",
	.vector_size = sizeof(u32),
	.format_trace = format_gtpu_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = GTPU_NEXT_N,
	.next_nodes = {
#define _(var, id, name) [GTPU_NEXT_##id] = (name),
	foreach_gtpu_detunnel_next
#undef _
	},
};

#endif

CLIB_MARCH_FN (gtpu_detunnel_init, clib_error_t *, vlib_main_t *CLIB_UNUSED(vm))
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));

	SIMD_VEC(ipv4_version) = SIMD_SPLAT(IPV4_VERSION);
	SIMD_VEC(ipv6_version) = SIMD_SPLAT(IPV6_VERSION);

	SIMD_VEC(drop_next) = SIMD_SPLAT(GTPU_NEXT_DROP);
	SIMD_VEC(ipv4_next) = SIMD_SPLAT(GTPU_NEXT_IPV4_DETUNNEL);
	SIMD_VEC(ipv6_next) = SIMD_SPLAT(GTPU_NEXT_IPV6_DETUNNEL);

	return 0;
}

static clib_error_t *gtpu_detunnel_init(vlib_main_t *CLIB_UNUSED(vm))
{
	gtpu_detunnel_main_t *idm = &gtpu_detunnel_main;
	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	idm->counter_if_index = pool_elts(im->sw_interfaces);

#define _(E, n)																\
	vlib_combined_counter_main_t *cm_##n = &idm->counters[GTPU_##E];	\
	cm_##n->name = "gtpu_" #n;											\
	cm_##n->stat_segment_name = "/detunnel/gtpu/" #n;					\
	vlib_validate_combined_counter(cm_##n, idm->counter_if_index);			\
	vlib_zero_combined_counter(cm_##n, idm->counter_if_index);

	foreach_detunnel_counter
#undef _

	return CLIB_MARCH_FN_SELECT(gtpu_detunnel_init) (vm);
}

VLIB_INIT_FUNCTION (gtpu_detunnel_init);