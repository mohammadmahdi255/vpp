#include <stdbool.h>

#include <vlib/vlib.h>

#include <vnet/ip/format.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/vnet.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include "detunnel.h"

#define foreach_udp_detunnel_next					\
	_(drop_next, DROP, "drop")						\
	_(l2tp_next, L2TP_DETUNNEL, "ip4-drop")			\
	_(gtpu_next, GTPU_DETUNNEL, "gtpu-detunnel")

#define foreach_udp_port	\
	_(l2tp_port)			\
	_(gtpu_port)

#define L2TP_PORT	1701
#define GTPU_PORT	2152

enum
{
#define _(var, id, name) UDP_NEXT_##id,
	foreach_udp_detunnel_next
#undef _
	UDP_NEXT_N,
};

#define _(var, id, name) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_udp_detunnel_next
#undef _

#define _(var) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_udp_port
#undef _

enum
{
#define _(id, name) UDP_##id,
	foreach_detunnel_counter
#undef _
	UDP_COUNTER_N,
};

typedef struct
{
	udp_header_t udp;
} udp_trace_t;

typedef struct
{
	u32 counter_if_index;
	vlib_counter_t cache_counters[MAX_IF_SIZE];
	vlib_combined_counter_main_t counters[UDP_COUNTER_N];
} udp_detunnel_main_t;

extern udp_detunnel_main_t udp_detunnel_main;
extern vlib_node_registration_t udp_detunnel;

static_always_inline void
udp_to_next(u16 *src_port, u16 *dst_port, u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE src_port_vec = SIMD_LOAD(src_port + i);
		SIMD_TYPE dst_port_vec = SIMD_LOAD(dst_port + i);
		SIMD_TYPE l2tp_mask_vec = (src_port_vec == SIMD_VEC(l2tp_port)) | (dst_port_vec == SIMD_VEC(l2tp_port));
		SIMD_TYPE gtpu_mask_vec = (src_port_vec == SIMD_VEC(gtpu_port)) | (dst_port_vec == SIMD_VEC(gtpu_port));

		SIMD_TYPE result = SIMD_VEC(drop_next) |
				(l2tp_mask_vec & SIMD_VEC(l2tp_next)) |
				(gtpu_mask_vec & SIMD_VEC(gtpu_next));

		SIMD_STORE(result, next + i);
	}
}

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
        const udp_header_t *udp, const u8 is_valid)
{
	if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) && (b->flags & VLIB_BUFFER_IS_TRACED)))
	{
		udp_trace_t *t = vlib_add_trace(vm, node, b, sizeof(udp_trace_t));
		t->udp = is_valid ? *udp : (udp_header_t){0};
	}
}

static_always_inline void
process_buffer_4x(vlib_main_t *vm, vlib_node_runtime_t *node,
		vlib_buffer_t* b[4], u16 src_port[4], u16 dst_port[4])
{
	const u32 sw_idx0 = vnet_buffer(b[0])->sw_if_index[VLIB_RX];
	const u32 sw_idx1 = vnet_buffer(b[1])->sw_if_index[VLIB_RX];
	const u32 sw_idx2 = vnet_buffer(b[2])->sw_if_index[VLIB_RX];
	const u32 sw_idx3 = vnet_buffer(b[3])->sw_if_index[VLIB_RX];

	const u8 sw_idx_eq = sw_idx0 == sw_idx1 && sw_idx2 == sw_idx3 && sw_idx0 == sw_idx2;

	const u8 is_valid0 = vlib_buffer_has_space(b[0], sizeof(udp_header_t));
	const u8 is_valid1 = vlib_buffer_has_space(b[1], sizeof(udp_header_t));
	const u8 is_valid2 = vlib_buffer_has_space(b[2], sizeof(udp_header_t));
	const u8 is_valid3 = vlib_buffer_has_space(b[3], sizeof(udp_header_t));

	const u16 bytes0 = is_valid0 ? sizeof(udp_header_t) : 0;
	const u16 bytes1 = is_valid1 ? sizeof(udp_header_t) : 0;
	const u16 bytes2 = is_valid2 ? sizeof(udp_header_t) : 0;
	const u16 bytes3 = is_valid3 ? sizeof(udp_header_t) : 0;

	const udp_header_t *udp0 = vlib_buffer_get_current(b[0]);
	const udp_header_t *udp1 = vlib_buffer_get_current(b[1]);
	const udp_header_t *udp2 = vlib_buffer_get_current(b[2]);
	const udp_header_t *udp3 = vlib_buffer_get_current(b[3]);

	vlib_buffer_advance(b[0], bytes0);
	vlib_buffer_advance(b[1], bytes1);
	vlib_buffer_advance(b[2], bytes2);
	vlib_buffer_advance(b[3], bytes3);

	src_port[0] = is_valid0 ? udp0->src_port : 0;
	src_port[1] = is_valid1 ? udp1->src_port : 0;
	src_port[2] = is_valid2 ? udp2->src_port : 0;
	src_port[3] = is_valid3 ? udp3->src_port : 0;

	dst_port[0] = is_valid0 ? udp0->dst_port : 0;
	dst_port[1] = is_valid1 ? udp1->dst_port : 0;
	dst_port[2] = is_valid2 ? udp2->dst_port : 0;
	dst_port[3] = is_valid3 ? udp3->dst_port : 0;

	udp_detunnel_main_t *udm = &udp_detunnel_main;

	if (PREDICT_TRUE(sw_idx_eq))
	{
		udm->cache_counters[sw_idx0].packets += is_valid0 + is_valid1 + is_valid2 + is_valid3;
		udm->cache_counters[sw_idx0].bytes += bytes0 + bytes1 + bytes2 + bytes3;
	}
	else
	{
		udm->cache_counters[sw_idx0].packets += is_valid0;
		udm->cache_counters[sw_idx1].packets += is_valid1;
		udm->cache_counters[sw_idx2].packets += is_valid2;
		udm->cache_counters[sw_idx3].packets += is_valid3;
		udm->cache_counters[sw_idx0].bytes += bytes0;
		udm->cache_counters[sw_idx1].bytes += bytes1;
		udm->cache_counters[sw_idx2].bytes += bytes2;
		udm->cache_counters[sw_idx3].bytes += bytes3;
	}

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
	{
		add_trace(vm, node, b[0], udp0, is_valid0);
		add_trace(vm, node, b[1], udp1, is_valid1);
		add_trace(vm, node, b[2], udp2, is_valid2);
		add_trace(vm, node, b[3], udp3, is_valid3);
	}
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *src_port, u16 *dst_port)
{
	udp_detunnel_main_t *udm = &udp_detunnel_main;
	const u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];

	const u8 is_valid = vlib_buffer_has_space(b, sizeof(udp_header_t));
	const u16 bytes = is_valid ? sizeof(udp_header_t) : 0;

	const udp_header_t *udp = vlib_buffer_get_current(b);
	vlib_buffer_advance(b, bytes);

	src_port[0] = is_valid ? udp->src_port : 0;
	dst_port[0] = is_valid ? udp->dst_port : 0;
	udm->cache_counters[sw_idx].packets += is_valid;
	udm->cache_counters[sw_idx].bytes += bytes;

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
		add_trace(vm, node, b, udp, is_valid);
}

VLIB_NODE_FN (udp_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
	u16 nexts[VLIB_FRAME_SIZE];
	u16 src_ports[VLIB_FRAME_SIZE];
	u16 dst_ports[VLIB_FRAME_SIZE];
	vlib_buffer_t **b = bufs;
	u16 *src_port = src_ports;
	u16 *dst_port = dst_ports;

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

		process_buffer_4x(vm, node, b, src_port, dst_port);

		b += 4;
		src_port += 4;
		dst_port += 4;
		n_left_from -= 4;
	}

	while (n_left_from > 0)
	{
		process_buffer_1x(vm, node, b[0], src_port, dst_port);

		b++;
		src_port++;
		dst_port++;
		n_left_from--;
	}

	for (u32 sw_idx = 0; sw_idx <= max_sw_if_index; sw_idx++)
	{
		vlib_counter_t *counter = &udm->cache_counters[sw_idx];
		vlib_increment_combined_counter(&udm->counters[UDP_PROCESSED], vm->thread_index,
				sw_idx, counter->packets, counter->bytes);

		counter->packets = 0;
		counter->bytes = 0;
	}

	udp_to_next(src_port, dst_port, nexts, frame->n_vectors);
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
	return format(s, "%U", format_udp_header, &t->udp, sizeof(udp_header_t));
}

VLIB_REGISTER_NODE (udp_detunnel) = {
	.name = "udp-detunnel",
	.vector_size = sizeof(u32),
	.format_trace = format_udp_detunnel_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = UDP_NEXT_N,
	.next_nodes = {
#define _(var, id, name) [UDP_NEXT_##id] = (name),
	foreach_udp_detunnel_next
#undef _
	},
};
#endif

CLIB_MARCH_FN (udp_detunnel_init, clib_error_t *, vlib_main_t *CLIB_UNUSED(vm))
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));

	SIMD_VEC(l2tp_port) = SIMD_SPLAT(clib_host_to_net_u32(L2TP_PORT));
	SIMD_VEC(gtpu_port) = SIMD_SPLAT(clib_host_to_net_u32(GTPU_PORT));

	SIMD_VEC(drop_next) = SIMD_SPLAT(UDP_NEXT_DROP);
	SIMD_VEC(l2tp_next) = SIMD_SPLAT(UDP_NEXT_L2TP_DETUNNEL);
	SIMD_VEC(gtpu_next) = SIMD_SPLAT(UDP_NEXT_GTPU_DETUNNEL);

	return 0;
}

static clib_error_t *udp_detunnel_init(vlib_main_t *vm)
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

	clib_memset(udm->cache_counters, 0, sizeof(udm->cache_counters));

	return CLIB_MARCH_FN_SELECT(udp_detunnel_init) (vm);
}

VLIB_INIT_FUNCTION (udp_detunnel_init);