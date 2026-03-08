#include <stdbool.h>

#include <vlib/vlib.h>

#include <vnet/ip/format.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/vnet.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include "detunnel.h"

#define foreach_tcp_detunnel_next									\
	_(detunnel_output_next, DETUNNEL_OUTPUT, "detunnel-output")		\
	_(failed_next, FAILED_DETUNNEL, "failed-detunnel")

#define foreach_tcp_port	\
	_(invalid_port)

#define INVALID_PORT	0

enum
{
#define _(var, id, name) TCP_NEXT_##id,
	foreach_tcp_detunnel_next
#undef _
	TCP_NEXT_N,
};

#define _(var, id, name) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_tcp_detunnel_next
#undef _

#define _(var) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_tcp_port
#undef _

enum
{
#define _(id, name) TCP_##id,
	foreach_detunnel_counter
#undef _
	TCP_COUNTER_N,
};

typedef struct
{
	tcp_header_t tcp;
} tcp_trace_t;

typedef struct
{
	u32 counter_if_index;
	vlib_combined_counter_main_t counters[TCP_COUNTER_N];
} tcp_detunnel_main_t;

typedef struct
{
	vlib_counter_t counters[MAX_IF_SIZE];
} tcp_detunnel_worker_t;

extern __thread tcp_detunnel_worker_t tcp_detunnel_worker;
extern tcp_detunnel_main_t tcp_detunnel_main;
extern vlib_node_registration_t tcp_detunnel;

static_always_inline void
tcp_to_next(u16 *src_port, u16 *dst_port, u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE src_port_vec = SIMD_LOAD(src_port + i);
		SIMD_TYPE dst_port_vec = SIMD_LOAD(dst_port + i);
		SIMD_TYPE failed_mask_vec = (src_port_vec == SIMD_VEC(invalid_port)) & (dst_port_vec == SIMD_VEC(invalid_port));

		SIMD_TYPE result = SIMD_VEC(detunnel_output_next) |
				(failed_mask_vec & SIMD_VEC(failed_next));

		SIMD_STORE(result, next + i);
	}
}

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
        const tcp_header_t *tcp)
{
	if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
	{
		tcp_trace_t *t = vlib_add_trace(vm, node, b, sizeof(tcp_trace_t));
		t->tcp = *tcp;
	}
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
	u16 *src_port, u16 *dst_port, u8 is_trace)
{
	tcp_detunnel_worker_t *udw = &tcp_detunnel_worker;
	const u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];
	vnet_buffer(b)->l4_hdr_offset = b->current_data;

	tcp_header_t *tcp = vlib_buffer_get_current(b);
	const u16 offset = clib_max(tcp_header_bytes(tcp), sizeof(tcp_header_t));

	if (PREDICT_FALSE(!vlib_buffer_has_space(b, offset)))
	{
		src_port[0] = INVALID_PORT;
		dst_port[0] = INVALID_PORT;
		goto trace;
	}

	vlib_buffer_advance(b, offset);
	udw->counters[sw_idx].packets++;
	udw->counters[sw_idx].bytes += offset;
	src_port[0] = tcp->src_port;
	dst_port[0] = tcp->dst_port;

trace:
	if (is_trace)
		add_trace(vm, node, b, tcp);
}

static_always_inline u64
tcp_detunnel_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_trace)
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

	tcp_detunnel_main_t *udm = &tcp_detunnel_main;
	tcp_detunnel_worker_t *udw = &tcp_detunnel_worker;

	for (u32 sw_idx = 0; sw_idx <= udm->counter_if_index; sw_idx++)
	{
		vlib_counter_t *counter = &udw->counters[sw_idx];
		vlib_increment_combined_counter(&udm->counters[TCP_PROCESSED], vm->thread_index,
				sw_idx, counter->packets, counter->bytes);

		counter->packets = 0;
		counter->bytes = 0;
	}

	tcp_to_next(src_ports, dst_ports, nexts, frame->n_vectors);
	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

VLIB_NODE_FN (tcp_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	return tcp_detunnel_inline(vm, node, frame, node->flags & VLIB_NODE_FLAG_TRACE);
}

#ifndef CLIB_MARCH_VARIANT
__thread tcp_detunnel_worker_t tcp_detunnel_worker;
tcp_detunnel_main_t tcp_detunnel_main;

static u8 *format_tcp_detunnel_trace(u8 *s, va_list *args)
{
	vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
	vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
	tcp_trace_t *t = va_arg(*args, tcp_trace_t *);
	return format(s, "%U", format_tcp_header, &t->tcp, sizeof(tcp_header_t));
}

VLIB_REGISTER_NODE (tcp_detunnel) = {
	.name = "tcp-detunnel",
	.vector_size = sizeof(u32),
	.format_trace = format_tcp_detunnel_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = TCP_NEXT_N,
	.next_nodes = {
#define _(var, id, name) [TCP_NEXT_##id] = (name),
	foreach_tcp_detunnel_next
#undef _
	},
};

void tcp_detunnel_counter_validate(u32 sw_if_index)
{
	tcp_detunnel_main_t *udm = &tcp_detunnel_main;

	clib_warning("interface max index %u", sw_if_index);

	if (PREDICT_FALSE(udm->counter_if_index < sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&udm->counters[TCP_##id], sw_if_index);
	foreach_detunnel_counter
#undef _

		for (u32 i = udm->counter_if_index + 1; i <= sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&udm->counters[TCP_##id], i);
	foreach_detunnel_counter
#undef _
		}

		udm->counter_if_index = sw_if_index;
	}
}

#endif

CLIB_MARCH_FN (tcp_detunnel_init, clib_error_t *, vlib_main_t __clib_unused *vm)
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));

	SIMD_VEC(invalid_port) = SIMD_SPLAT(clib_host_to_net_u16(INVALID_PORT));

	SIMD_VEC(detunnel_output_next) = SIMD_SPLAT(TCP_NEXT_DETUNNEL_OUTPUT);
	SIMD_VEC(failed_next) = SIMD_SPLAT(TCP_NEXT_FAILED_DETUNNEL);

	return 0;
}

static clib_error_t *
tcp_detunnel_worker_init(vlib_main_t __clib_unused *vm)
{
	tcp_detunnel_worker_t *udw = &tcp_detunnel_worker;
	clib_memset(udw->counters, 0, sizeof(udw->counters));
	return 0;
}

static clib_error_t *
tcp_detunnel_init(vlib_main_t *vm)
{
	tcp_detunnel_main_t *udm = &tcp_detunnel_main;
	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	udm->counter_if_index = pool_elts(im->sw_interfaces);

#define _(E, n)																\
	vlib_combined_counter_main_t *cm_##n = &udm->counters[TCP_##E];			\
	cm_##n->name = "tcp_" #n;												\
	cm_##n->stat_segment_name = "/detunnel/tcp/" #n;						\
	vlib_validate_combined_counter(cm_##n, udm->counter_if_index);			\
	vlib_zero_combined_counter(cm_##n, udm->counter_if_index);

	foreach_detunnel_counter
#undef _

	return CLIB_MARCH_FN_SELECT(tcp_detunnel_init) (vm);
}

VLIB_WORKER_INIT_FUNCTION (tcp_detunnel_worker_init);
VLIB_INIT_FUNCTION (tcp_detunnel_init);