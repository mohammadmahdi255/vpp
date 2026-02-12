#include <stdbool.h>

#include <vlib/vlib.h>

#include <vnet/ip/format.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/vnet.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include "detunnel.h"

#define foreach_ipv4_detunnel_next						\
	_(drop_next, DROP, "drop")							\
	_(ipv4_next, IPV4_DETUNNEL, "ipv4-detunnel")		\
	_(ipv6_next, IPV6_DETUNNEL, "ipv6-detunnel")		\
	_(gre_next, GRE_DETUNNEL, "gre-detunnel")			\
	_(tcp_next, TCP_DETUNNEL, "tcp-detunnel")			\
	_(udp_next, UDP_DETUNNEL, "udp-detunnel")			\
	_(failed_next, FAILED_DETUNNEL, "failed-detunnel")

enum
{
#define _(var, id, name) IPV4_NEXT_##id,
	foreach_ipv4_detunnel_next
#undef _
	IPV4_NEXT_N,
};

#define _(var, id, name) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_ipv4_detunnel_next
#undef _

enum
{
#define _(id, name) IPV4_##id,
	foreach_detunnel_counter
#undef _
	IPV4_COUNTER_N,
};

typedef struct
{
	ip4_header_t ip4;
} ip4_trace_t;

typedef struct {
	u32 counter_if_index;
	vlib_combined_counter_main_t counters[IPV4_COUNTER_N];
} ipv4_detunnel_main_t;

typedef struct
{
	vlib_counter_t counters[MAX_IF_SIZE];
} ipv4_detunnel_worker_t;

static __thread ipv4_detunnel_worker_t ipv4_detunnel_worker;
extern ipv4_detunnel_main_t ipv4_detunnel_main;
extern vlib_node_registration_t ipv4_detunnel;

static_always_inline void
ipv4_to_next(u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE next_vec = SIMD_LOAD(next + i);
		SIMD_TYPE ipv4_mask_vec = (next_vec == SIMD_VEC(ipv4_protocol));
		SIMD_TYPE ipv6_mask_vec = (next_vec == SIMD_VEC(ipv6_protocol));
		SIMD_TYPE gre_mask_vec = (next_vec == SIMD_VEC(gre_protocol));
		SIMD_TYPE tcp_mask_vec = (next_vec == SIMD_VEC(tcp_protocol));
		SIMD_TYPE udp_mask_vec = (next_vec == SIMD_VEC(udp_protocol));
		SIMD_TYPE failed_mask_vec = (next_vec == SIMD_VEC(invalid_protocol));

		SIMD_TYPE result = SIMD_VEC(drop_next) |
				(ipv4_mask_vec & SIMD_VEC(ipv4_next)) |
				(ipv6_mask_vec & SIMD_VEC(ipv6_next)) |
				(gre_mask_vec & SIMD_VEC(gre_next)) |
				(tcp_mask_vec & SIMD_VEC(tcp_next)) |
				(udp_mask_vec & SIMD_VEC(udp_next)) |
				(failed_mask_vec & SIMD_VEC(failed_next));

		SIMD_STORE(result, next + i);
	}
}

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		const ip4_header_t *ip4)
{
	if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
	{
		ip4_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
		t->ip4 = *ip4;
	}
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next, u8 is_trace)
{
	ipv4_detunnel_worker_t *idw = &ipv4_detunnel_worker;
	u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];
	vnet_buffer(b)->l3_hdr_offset = b->current_data;

	const ip4_header_t *ip4 = vlib_buffer_get_current(b);
	const u16 ip4_hdr_len = clib_max(ip4_header_bytes(ip4), sizeof(ip4_header_t));
	const u16 len = vlib_buffer_length_in_chain(vm, b);
	const u16 ip4_len = clib_net_to_host_u16(ip4->length);
	const i32 ip4_pad_len = len - ip4_len;

	if (PREDICT_FALSE(ip4_pad_len < 0 || !vlib_buffer_has_space(b, ip4_hdr_len)))
	{
		next[0] = IP_PROTOCOL_INVALID;
		goto trace;
	}

	vlib_buffer_advance(b, ip4_hdr_len);
	idw->counters[sw_idx].packets++;
	idw->counters[sw_idx].bytes += ip4_hdr_len;
	next[0] = ip4->protocol;

trace:
	if (is_trace)
		add_trace(vm, node, b, ip4);
}

static_always_inline u64
ipv4_detunnel_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_trace)
{
	vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
	u16 nexts[VLIB_FRAME_SIZE];
	u16 *next = nexts;

	vlib_buffer_t **b = bufs;

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

		process_buffer_1x(vm, node, b[0], &next[0], is_trace);
		process_buffer_1x(vm, node, b[1], &next[1], is_trace);
		process_buffer_1x(vm, node, b[2], &next[2], is_trace);
		process_buffer_1x(vm, node, b[3], &next[3], is_trace);

		b += 4;
		next += 4;
		n_left_from -= 4;
	}

	while (n_left_from > 0)
	{
		process_buffer_1x(vm, node, b[0], next, is_trace);

		b++;
		next++;
		n_left_from--;
	}

	ipv4_detunnel_main_t *idm = &ipv4_detunnel_main;
	ipv4_detunnel_worker_t *idw = &ipv4_detunnel_worker;

	for (u32 sw_idx = 0; sw_idx <= idm->counter_if_index; sw_idx++)
	{
		vlib_counter_t *counter = &idw->counters[sw_idx];
		vlib_increment_combined_counter(&idm->counters[IPV4_PROCESSED], vm->thread_index,
				sw_idx, counter->packets, counter->bytes);

		counter->packets = 0;
		counter->bytes = 0;
	}

	ipv4_to_next(nexts, frame->n_vectors);
	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

VLIB_NODE_FN (ipv4_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	return ipv4_detunnel_inline(vm, node, frame, node->flags & VLIB_NODE_FLAG_TRACE);
}

#ifndef CLIB_MARCH_VARIANT
ipv4_detunnel_main_t ipv4_detunnel_main;

static u8 *format_ipv4_trace(u8 *s, va_list *args)
{
	vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
	vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
	ip4_trace_t *t = va_arg(*args, ip4_trace_t *);
	return format(s, "%U", format_ip4_header, &t->ip4, ip4_header_bytes(&t->ip4));
}

VLIB_REGISTER_NODE (ipv4_detunnel) = {
	.name = "ipv4-detunnel",
	.vector_size = sizeof(u32),
	.format_trace = format_ipv4_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = IPV4_NEXT_N,
	.next_nodes = {
#define _(var, id, name) [IPV4_NEXT_##id] = (name),
	foreach_ipv4_detunnel_next
#undef _
	},
};

void ipv4_detunnel_counter_validate(u32 sw_if_index)
{
	ipv4_detunnel_main_t *idm = &ipv4_detunnel_main;

	if (PREDICT_FALSE(idm->counter_if_index < sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&idm->counters[IPV4_##id], sw_if_index);
	foreach_detunnel_counter
#undef _

		for (u32 i = idm->counter_if_index + 1; i <= sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&idm->counters[IPV4_##id], i);
	foreach_detunnel_counter
#undef _
		}

		idm->counter_if_index = sw_if_index;
	}
}

#endif

CLIB_MARCH_FN (ipv4_detunnel_init, clib_error_t *, vlib_main_t __clib_unused *vm)
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));

	SIMD_VEC(drop_next) = SIMD_SPLAT(IPV4_NEXT_DROP);
	SIMD_VEC(ipv4_next) = SIMD_SPLAT(IPV4_NEXT_IPV4_DETUNNEL);
	SIMD_VEC(ipv6_next) = SIMD_SPLAT(IPV4_NEXT_IPV6_DETUNNEL);
	SIMD_VEC(gre_next) = SIMD_SPLAT(IPV4_NEXT_GRE_DETUNNEL);
	SIMD_VEC(tcp_next) = SIMD_SPLAT(IPV4_NEXT_TCP_DETUNNEL);
	SIMD_VEC(udp_next) = SIMD_SPLAT(IPV4_NEXT_UDP_DETUNNEL);
	SIMD_VEC(failed_next) = SIMD_SPLAT(IPV4_NEXT_FAILED_DETUNNEL);

	return 0;
}

static clib_error_t *
ipv4_detunnel_worker_init(vlib_main_t __clib_unused *vm)
{
	ipv4_detunnel_worker_t *idw = &ipv4_detunnel_worker;
	clib_memset(idw->counters, 0, sizeof(idw->counters));
	return 0;
}

static clib_error_t *
ipv4_detunnel_init(vlib_main_t *vm)
{
	ipv4_detunnel_main_t *idm = &ipv4_detunnel_main;
	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	idm->counter_if_index = pool_elts(im->sw_interfaces);

#define _(E, n)																\
	vlib_combined_counter_main_t *cm_##n = &idm->counters[IPV4_##E];	\
	cm_##n->name = "ipv4_" #n;											\
	cm_##n->stat_segment_name = "/detunnel/ipv4/" #n;					\
	vlib_validate_combined_counter(cm_##n, idm->counter_if_index);			\
	vlib_zero_combined_counter(cm_##n, idm->counter_if_index);

	foreach_detunnel_counter
#undef _

	return CLIB_MARCH_FN_SELECT(ipv4_detunnel_init) (vm);
}

VLIB_WORKER_INIT_FUNCTION (ipv4_detunnel_worker_init);
VLIB_INIT_FUNCTION (ipv4_detunnel_init);