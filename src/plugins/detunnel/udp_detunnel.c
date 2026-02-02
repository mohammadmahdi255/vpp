#include <stdbool.h>

#include <vlib/vlib.h>

#include <vnet/udp/udp_packet.h>
#include <vnet/vnet.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include "detunnel.h"
#include "gtpu/gtpu.h"

#define foreach_udp_detunnel_next_node	\
	_(DROP, "drop")						\
	_(L2TP_DETUNNEL, "ip4-drop")		\
	_(GPRS_DETUNNEL, "ip6-drop")

#define foreach_next_protocol	\
	_(l2tp_protocol)			\
	_(gprs_protocol)

#define foreach_next_node 	\
	_(drop_next)			\
	_(l2tp_next)			\
	_(gprs_next)

/*
#ifndef CLIB_MARCH_VARIANT
#define _(name)				\
	u16x32 name##_u16x32;	\
	u16x16 name##_u16x16;	\
	u16x8 name##_u16x8;

foreach_next_protocol
foreach_next_node
#undef _
#else
#define _(name)						\
	extern u16x32 name##_u16x32;	\
	extern u16x16 name##_u16x16;	\
	extern u16x8 name##_u16x8;

foreach_next_protocol
foreach_next_node
#undef _
#endif
*/

enum
{
#define _(id, name) UDP_##id,
	foreach_detunnel_counter
#undef _
	UDP_COUNTER_N,
};

enum
{
#define _(id, name) NEXT_NODE_##id,
	foreach_udp_detunnel_next_node
#undef _
	UDP_NEXT_NODE_N,
};

typedef struct
{
	udp_header_t udp;
	u32 sw_if_index;
} udp_trace_t;

typedef struct
{
	u32 counter_if_index;
	vlib_combined_counter_main_t counters[UDP_COUNTER_N];
} udp_detunnel_main_t;

extern udp_detunnel_main_t udp_detunnel_main;
extern vlib_node_registration_t udp_detunnel;

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
        const udp_header_t *udp)
{
	if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) && (b->flags & VLIB_BUFFER_IS_TRACED)))
	{
		udp_trace_t *t = vlib_add_trace(vm, node, b, sizeof(udp_trace_t));
		t->udp = *udp;
		t->sw_if_index = vnet_buffer(b)->sw_if_index[VLIB_RX];
	}
}

static_always_inline u32 get_next_node_1x(u16 src_port, u16 dst_port)
{
	return src_port == 0x6808 || dst_port == 0x6808 ? NEXT_NODE_GPRS_DETUNNEL :
			src_port == 0xA506 || dst_port == 0xA506 ? NEXT_NODE_L2TP_DETUNNEL :
			NEXT_NODE_ERROR_DROP;
}

static_always_inline bool
process_buffer_4x(vlib_main_t *vm, vlib_node_runtime_t *node,
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

	u8 error = 0;
	error |= len0 < sizeof(udp_header_t);
	error |= len1 < sizeof(udp_header_t);
	error |= len2 < sizeof(udp_header_t);
	error |= len3 < sizeof(udp_header_t);

	if (PREDICT_FALSE(error))
		return false;

	const udp_header_t *udp0 = vlib_buffer_get_current(b[0]);
	const udp_header_t *udp1 = vlib_buffer_get_current(b[1]);
	const udp_header_t *udp2 = vlib_buffer_get_current(b[2]);
	const udp_header_t *udp3 = vlib_buffer_get_current(b[3]);

	vlib_buffer_advance(b[0], sizeof(udp_header_t));
	vlib_buffer_advance(b[1], sizeof(udp_header_t));
	vlib_buffer_advance(b[2], sizeof(udp_header_t));
	vlib_buffer_advance(b[3], sizeof(udp_header_t));

	next[0] = get_next_node_1x(udp0->src_port, udp0->dst_port);
	next[1] = get_next_node_1x(udp1->src_port, udp1->dst_port);
	next[2] = get_next_node_1x(udp2->src_port, udp2->dst_port);
	next[3] = get_next_node_1x(udp3->src_port, udp3->dst_port);

	udp_detunnel_main_t *udm = &udp_detunnel_main;
	vlib_increment_combined_counter(&udm->counters[UDP_TOTAL],
		vm->thread_index, sw_idx0, 1, len0);
	vlib_increment_combined_counter(&udm->counters[UDP_PROCESSED],
		vm->thread_index, sw_idx0, 1, sizeof(udp_header_t));
	vlib_increment_combined_counter(&udm->counters[UDP_TOTAL],
		vm->thread_index, sw_idx1, 1, len1);
	vlib_increment_combined_counter(&udm->counters[UDP_PROCESSED],
		vm->thread_index, sw_idx1, 1, sizeof(udp_header_t));
	vlib_increment_combined_counter(&udm->counters[UDP_TOTAL],
		vm->thread_index, sw_idx2, 1, len2);
	vlib_increment_combined_counter(&udm->counters[UDP_PROCESSED],
		vm->thread_index, sw_idx2, 1, sizeof(udp_header_t));
	vlib_increment_combined_counter(&udm->counters[UDP_TOTAL],
		vm->thread_index, sw_idx3, 1, len3);
	vlib_increment_combined_counter(&udm->counters[UDP_PROCESSED],
		vm->thread_index, sw_idx3, 1, sizeof(udp_header_t));

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
	{
		add_trace(vm, node, b[0], udp0);
		add_trace(vm, node, b[1], udp1);
		add_trace(vm, node, b[2], udp2);
		add_trace(vm, node, b[3], udp3);
	}

	return true;
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next)
{
	udp_detunnel_main_t *udm = &udp_detunnel_main;
	u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];

	vlib_increment_combined_counter(&udm->counters[UDP_TOTAL], vm->thread_index,
			sw_idx, 1, b->current_length);

	if (PREDICT_FALSE(b->current_length < sizeof(udp_header_t)))
	{
		vlib_increment_combined_counter(&udm->counters[UDP_FAILED], vm->thread_index,
				sw_idx, 1, b->current_length);
		next[0] = NEXT_NODE_ERROR_DROP;
		return;
	}

	const udp_header_t *udp = vlib_buffer_get_current(b);
	vlib_buffer_advance(b, sizeof(udp_header_t));
	vlib_increment_combined_counter(&udm->counters[UDP_PROCESSED], vm->thread_index,
			sw_idx, 1, sizeof(udp_header_t));

	next[0] = get_next_node_1x(udp->src_port, udp->dst_port);

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
		add_trace(vm, node, b, udp);
}

VLIB_NODE_FN (udp_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
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

	udp_detunnel_main_t *udm = &udp_detunnel_main;

	if (PREDICT_FALSE(udm->counter_if_index < max_sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&udm->counters[UDP_##id], max_sw_if_index);
	foreach_detunnel_counter
#undef _

		for (u32 i = udm->counter_if_index + 1; i <= max_sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&udm->counters[UDP_##id], i);
	foreach_detunnel_counter
#undef _
		}

		udm->counter_if_index = max_sw_if_index;
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

	CLIB_MARCH_FN_SELECT(ethertype_to_next) (nexts, frame->n_vectors);

	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

#ifndef CLIB_MARCH_VARIANT
udp_detunnel_main_t udp_detunnel_main;

static u8 *format_udp_detunnel_trace(u8 *s, va_list *args)
{
	vlib_main_t *CLIB_UNUSED(vm)   = va_arg(*args, vlib_main_t *);
	vlib_node_t *CLIB_UNUSED(node) = va_arg(*args, vlib_node_t *);
	udp_trace_t *t = va_arg(*args, udp_trace_t *);
	return format(s, "udp detunnel: if index %u src %U dst %U ethertype 0x%04x",
			t->sw_if_index);
}

VLIB_REGISTER_NODE (udp_detunnel) = {
	.name = "udp-detunnel",
	.vector_size = sizeof(u32),
	.format_trace = format_udp_detunnel_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = UDP_NEXT_NODE_N,
	.next_nodes = {
#define _(id, name) [NEXT_NODE_##id] = (name),
	foreach_udp_detunnel_next_node
#undef _
	},
};
#endif

// CLIB_MARCH_FN (udp_detunnel_init, clib_error_t *, vlib_main_t *CLIB_UNUSED(vm))
// {
// 	clib_warning("size: %lu %s", SIMD_SIZE, STR(SIMD_TYPE));

// 	SIMD_VEC(l2tp_protocol) = SIMD_SPLAT(IP_PROTOCOL_TCP);
// 	SIMD_VEC(gprs_protocol) = SIMD_SPLAT(IP_PROTOCOL_UDP);

// 	SIMD_VEC(drop_next) = SIMD_SPLAT(NEXT_NODE_DROP);
// 	SIMD_VEC(l2tp_next) = SIMD_SPLAT(NEXT_NODE_L2TP_DETUNNEL);
// 	SIMD_VEC(gprs_next) = SIMD_SPLAT(NEXT_NODE_GPRS_DETUNNEL);

// 	return 0;
// }

static clib_error_t *udp_detunnel_init(vlib_main_t *CLIB_UNUSED(vm))
{
	udp_detunnel_main_t *udm = &udp_detunnel_main;
	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	udm->counter_if_index = pool_elts(im->sw_interfaces);

#define _(E, n)																\
	vlib_combined_counter_main_t *cm_##n = &udm->counters[UDP_##E];	\
	cm_##n->name = "udp_" #n;											\
	cm_##n->stat_segment_name = "/detunnel/udp/" #n;					\
	vlib_validate_combined_counter(cm_##n, udm->counter_if_index);			\
	vlib_zero_combined_counter(cm_##n, udm->counter_if_index);

	foreach_detunnel_counter
#undef _

	// CLIB_MARCH_FN_SELECT (udp_detunnel_init) (vm);

	return 0;
}

VLIB_INIT_FUNCTION (udp_detunnel_init);