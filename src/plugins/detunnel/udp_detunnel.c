#include <stdbool.h>

#include <vlib/vlib.h>

#include <vnet/ip/format.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/vnet.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include "detunnel.h"

#define foreach_udp_detunnel_next									\
	_(detunnel_output_next, DETUNNEL_OUTPUT, "detunnel-output")		\
	_(l2tp_next, L2TP_DETUNNEL, "l2tp-detunnel")					\
	_(gtpu_next, GTPU_DETUNNEL, "gtpu-detunnel")					\
	_(failed_next, FAILED_DETUNNEL, "failed-detunnel")

#define foreach_udp_port	\
	_(l2tp_port, _, _)			\
	_(gtpu_port, _, _)			\
	_(invalid_port, _, _)

#define L2TP_PORT		1701
#define GTPU_PORT		2152
#define INVALID_PORT	0

enum
{
#define _(var, id, name) UDP_NEXT_##id,
	foreach_udp_detunnel_next
#undef _
	UDP_NEXT_N,
};

#define _(var, id, name) static simd_u16_t simd_u16(var);

foreach_udp_detunnel_next
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
	vlib_combined_counter_main_t counters[UDP_COUNTER_N];
} udp_detunnel_main_t;

typedef struct
{
	vlib_counter_t counters[MAX_IF_SIZE];
} udp_detunnel_worker_t;

extern __thread udp_detunnel_worker_t udp_detunnel_worker;
extern udp_detunnel_main_t udp_detunnel_main;
extern vlib_node_registration_t udp_detunnel;

static_always_inline void
udp_to_next(u16 *src_port, u16 *dst_port, u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += simd_u16_size)
	{
		simd_u16_t src_port_vec = simd_u16_load(src_port + i);
		simd_u16_t dst_port_vec = simd_u16_load(dst_port + i);
		simd_u16_t l2tp_mask_vec = (src_port_vec == simd_u16(l2tp_port)) | (dst_port_vec == simd_u16(l2tp_port));
		simd_u16_t gtpu_mask_vec = (src_port_vec == simd_u16(gtpu_port)) | (dst_port_vec == simd_u16(gtpu_port));
		simd_u16_t failed_mask_vec = (src_port_vec == simd_u16(invalid_port)) & (dst_port_vec == simd_u16(invalid_port));

		simd_u16_t result = simd_u16(detunnel_output_next) |
				(l2tp_mask_vec & simd_u16(l2tp_next)) |
				(gtpu_mask_vec & simd_u16(gtpu_next)) |
				(failed_mask_vec & simd_u16(failed_next));

		simd_u16_store(result, next + i);
	}
}

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
        const udp_header_t *udp)
{
	if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
	{
		udp_trace_t *t = vlib_add_trace(vm, node, b, sizeof(udp_trace_t));
		t->udp = *udp;
	}
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
	u16 *src_port, u16 *dst_port, u8 is_trace)
{
	udp_detunnel_worker_t *udw = &udp_detunnel_worker;
	const u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];
	vnet_buffer(b)->l4_hdr_offset = b->current_data;

	const udp_header_t *udp = vlib_buffer_get_current(b);

	if (PREDICT_FALSE(!vlib_buffer_has_space(b, sizeof(udp_header_t))))
	{
		src_port[0] = INVALID_PORT;
		dst_port[0] = INVALID_PORT;
		goto trace;
	}

	vlib_buffer_advance(b, sizeof(udp_header_t));
	udw->counters[sw_idx].packets++;
	udw->counters[sw_idx].bytes += sizeof(udp_header_t);
	src_port[0] = udp->src_port;
	dst_port[0] = udp->dst_port;

trace:
	if (is_trace)
		add_trace(vm, node, b, udp);
}

static_always_inline u64
udp_detunnel_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_trace)
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

		process_buffer_1x(vm, node, b[0], &src_port[0], &dst_port[0], is_trace);
		process_buffer_1x(vm, node, b[1], &src_port[1], &dst_port[1], is_trace);
		process_buffer_1x(vm, node, b[2], &src_port[2], &dst_port[2], is_trace);
		process_buffer_1x(vm, node, b[3], &src_port[3], &dst_port[3], is_trace);

		b += 4;
		src_port += 4;
		dst_port += 4;
		n_left_from -= 4;
	}

	while (n_left_from > 0)
	{
		process_buffer_1x(vm, node, b[0], src_port, dst_port, is_trace);

		b++;
		src_port++;
		dst_port++;
		n_left_from--;
	}

	udp_detunnel_main_t *udm = &udp_detunnel_main;
	udp_detunnel_worker_t *udw = &udp_detunnel_worker;

	for (u32 sw_idx = 0; sw_idx <= udm->counter_if_index; sw_idx++)
	{
		vlib_counter_t *counter = &udw->counters[sw_idx];
		vlib_increment_combined_counter(&udm->counters[UDP_PROCESSED], vm->thread_index,
				sw_idx, counter->packets, counter->bytes);

		counter->packets = 0;
		counter->bytes = 0;
	}

	udp_to_next(src_ports, dst_ports, nexts, frame->n_vectors);
	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

VLIB_NODE_FN (udp_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	return udp_detunnel_inline(vm, node, frame, node->flags & VLIB_NODE_FLAG_TRACE);
}

#ifndef CLIB_MARCH_VARIANT
__thread udp_detunnel_worker_t udp_detunnel_worker;
udp_detunnel_main_t udp_detunnel_main;

static u8 *format_udp_detunnel_trace(u8 *s, va_list *args)
{
	vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
	vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
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

void udp_detunnel_counter_validate(u32 sw_if_index)
{
	udp_detunnel_main_t *udm = &udp_detunnel_main;

	clib_warning("interface max index %u", sw_if_index);

	if (PREDICT_FALSE(udm->counter_if_index < sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&udm->counters[UDP_##id], sw_if_index);
	foreach_detunnel_counter
#undef _

		for (u32 i = udm->counter_if_index + 1; i <= sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&udm->counters[UDP_##id], i);
	foreach_detunnel_counter
#undef _
		}

		udm->counter_if_index = sw_if_index;
	}
}

#endif

CLIB_MARCH_FN (udp_detunnel_init, clib_error_t *, vlib_main_t __clib_unused *vm)
{
	clib_warning("size: %lu %s", simd_u16_size, CLIB_STRING_MACRO(simd_u16_t));

	simd_u16(l2tp_port) = simd_u16_splat(clib_host_to_net_u16(L2TP_PORT));
	simd_u16(gtpu_port) = simd_u16_splat(clib_host_to_net_u16(GTPU_PORT));
	simd_u16(invalid_port) = simd_u16_splat(clib_host_to_net_u16(INVALID_PORT));

	simd_u16(detunnel_output_next) = simd_u16_splat(UDP_NEXT_DETUNNEL_OUTPUT);
	simd_u16(l2tp_next) = simd_u16_splat(UDP_NEXT_L2TP_DETUNNEL);
	simd_u16(gtpu_next) = simd_u16_splat(UDP_NEXT_GTPU_DETUNNEL);
	simd_u16(failed_next) = simd_u16_splat(UDP_NEXT_FAILED_DETUNNEL);

	return 0;
}

static clib_error_t *
udp_detunnel_worker_init(vlib_main_t __clib_unused *vm)
{
	udp_detunnel_worker_t *udw = &udp_detunnel_worker;
	clib_memset(udw->counters, 0, sizeof(udw->counters));
	return 0;
}

static clib_error_t *
udp_detunnel_init(vlib_main_t *vm)
{
	udp_detunnel_main_t *udm = &udp_detunnel_main;
	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	udm->counter_if_index = pool_elts(im->sw_interfaces);

#define _(E, n)																\
	vlib_combined_counter_main_t *cm_##n = &udm->counters[UDP_##E];			\
	cm_##n->name = "udp_" #n;												\
	cm_##n->stat_segment_name = "/detunnel/udp/" #n;						\
	vlib_validate_combined_counter(cm_##n, udm->counter_if_index);			\
	vlib_zero_combined_counter(cm_##n, udm->counter_if_index);

	foreach_detunnel_counter
#undef _

	return CLIB_MARCH_FN_SELECT(udp_detunnel_init) (vm);
}

VLIB_WORKER_INIT_FUNCTION (udp_detunnel_worker_init);
VLIB_INIT_FUNCTION (udp_detunnel_init);