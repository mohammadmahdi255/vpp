#include <stdbool.h>

#include <vlib/vlib.h>

#include <vnet/ip/format.h>
#include <vnet/ip/ip_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/vnet.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include "detunnel.h"

#define foreach_ipv6_detunnel_next							\
	_(ipv6_etc_next, IPV6_ETC_DETUNNEL, "drop")				\
	_(ipv4_next, IPV4_DETUNNEL, "ipv4-detunnel")			\
	_(ipv6_next, IPV6_DETUNNEL, "ipv6-detunnel")			\
	_(ipv6_frag_next, IPV6_FRAG_DETUNNEL, "ip6-input")		\
	_(gre_next, GRE_DETUNNEL, "gre-detunnel")				\
	_(tcp_next, TCP_DETUNNEL, "tcp-detunnel")			\
	_(udp_next, UDP_DETUNNEL, "udp-detunnel")				\
	_(failed_next, FAILED_DETUNNEL, "failed-detunnel")

enum
{
#define _(var, id, name) IPV6_NEXT_##id,
	foreach_ipv6_detunnel_next
#undef _
	IPV6_NEXT_N,
};

#define _(var, id, name) static simd_u16_t simd_u16(var);

foreach_ipv6_detunnel_next
#undef _

enum
{
#define _(id, name) IPV6_##id,
	foreach_detunnel_counter
#undef _
	IPV6_COUNTER_N,
};

typedef struct
{
	ip6_header_t ip6;
} ip6_trace_t;

typedef struct {
	u32 counter_if_index;
	vlib_combined_counter_main_t counters[IPV6_COUNTER_N];
} ipv6_detunnel_main_t;

typedef struct
{
	vlib_counter_t counters[MAX_IF_SIZE];
} ipv6_detunnel_worker_t;

extern __thread ipv6_detunnel_worker_t ipv6_detunnel_worker;
extern ipv6_detunnel_main_t ipv6_detunnel_main;
extern vlib_node_registration_t ipv6_detunnel;

static_always_inline void
ipv6_to_next(u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += simd_u16_size)
	{
		simd_u16_t next_vec = simd_u16_load(next + i);
		simd_u16_t ipv4_mask_vec = (next_vec == simd_u16(ipv4_protocol));
		simd_u16_t ipv6_mask_vec = (next_vec == simd_u16(ipv6_protocol));
		simd_u16_t ipv6_frag_mask_vec = (next_vec == simd_u16(ipv6_frag_protocol));
		simd_u16_t gre_mask_vec = (next_vec == simd_u16(gre_protocol));
		simd_u16_t tcp_mask_vec = (next_vec == simd_u16(tcp_protocol));
		simd_u16_t udp_mask_vec = (next_vec == simd_u16(udp_protocol));
		simd_u16_t failed_mask_vec = (next_vec == simd_u16(invalid_protocol));

		simd_u16_t result = simd_u16(ipv6_etc_next) |
				(ipv4_mask_vec & simd_u16(ipv4_next)) |
				(ipv6_mask_vec & simd_u16(ipv6_next)) |
				(ipv6_frag_mask_vec & simd_u16(ipv6_frag_next)) |
				(gre_mask_vec & simd_u16(gre_next)) |
				(tcp_mask_vec & simd_u16(tcp_next)) |
				(udp_mask_vec & simd_u16(udp_next)) |
				(failed_mask_vec & simd_u16(failed_next));

		simd_u16_store(result, next + i);
	}
}

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		const ip6_header_t *ip6)
{
	if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
	{
		ip6_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
		t->ip6 = *ip6;
	}
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next, u8 is_trace)
{
	ipv6_detunnel_worker_t *idw = &ipv6_detunnel_worker;
	u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];
	vnet_buffer(b)->l3_hdr_offset = b->current_data;

	const ip6_header_t *ip6 = vlib_buffer_get_current(b);
	const u16 payload_len = clib_net_to_host_u16(ip6->payload_length);
	const u16 len = vlib_buffer_length_in_chain(vm, b);
	const u16 ip6_len = payload_len + sizeof(ip6_header_t);

	if (PREDICT_FALSE(len < ip6_len || !vlib_buffer_has_space(b, sizeof(ip6_header_t))))
	{
		next[0] = IP_PROTOCOL_INVALID;
		goto trace;
	}

	const void *data = ip6;
	u16 offset = sizeof(ip6_header_t);
	u8 protocol = ip6->protocol;

	while (ip6_ext_hdr(protocol))
	{
		const ip6_ext_header_t *ext_hdr = data + offset;

		if (PREDICT_FALSE(!vlib_buffer_has_space(b, offset + sizeof(ip6_ext_header_t))))
		{
			next[0] = IP_PROTOCOL_INVALID;
			goto trace;
		}

		offset += protocol == IP_PROTOCOL_IPSEC_AH ? ip6_ext_authhdr_len(ext_hdr) : ip6_ext_header_len(ext_hdr);
		protocol = ext_hdr->next_hdr;
	}

	next[0] = protocol;
	vnet_buffer(b)->ip.save_protocol = protocol;

	if (PREDICT_TRUE(protocol != IP_PROTOCOL_IPV6_FRAGMENTATION))
	{
		vlib_buffer_advance(b, offset);
		idw->counters[sw_idx].packets++;
		idw->counters[sw_idx].bytes += offset;
	}

trace:
	if (is_trace)
		add_trace(vm, node, b, ip6);
}

static_always_inline u64
ipv6_detunnel_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_trace)
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

	ipv6_detunnel_main_t *idm = &ipv6_detunnel_main;
	ipv6_detunnel_worker_t *idw = &ipv6_detunnel_worker;

	for (u32 sw_idx = 0; sw_idx <= idm->counter_if_index; sw_idx++)
	{
		vlib_counter_t *counter = &idw->counters[sw_idx];
		vlib_increment_combined_counter(&idm->counters[IPV6_PROCESSED], vm->thread_index,
				sw_idx, counter->packets, counter->bytes);

		counter->packets = 0;
		counter->bytes = 0;
	}

	ipv6_to_next(nexts, frame->n_vectors);
	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

VLIB_NODE_FN (ipv6_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	return ipv6_detunnel_inline(vm, node, frame, node->flags & VLIB_NODE_FLAG_TRACE);
}

#ifndef CLIB_MARCH_VARIANT
__thread ipv6_detunnel_worker_t ipv6_detunnel_worker;
ipv6_detunnel_main_t ipv6_detunnel_main;

static u8 *format_ipv6_trace(u8 *s, va_list *args)
{
	vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
	vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
	ip6_trace_t *t = va_arg(*args, ip6_trace_t *);
	return format(s, "%U", format_ip6_header, &t->ip6, sizeof(ip6_header_t));
}

VLIB_REGISTER_NODE (ipv6_detunnel) = {
	.name = "ipv6-detunnel",
	.vector_size = sizeof(u32),
	.format_trace = format_ipv6_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = IPV6_NEXT_N,
	.next_nodes = {
#define _(var, id, name) [IPV6_NEXT_##id] = (name),
	foreach_ipv6_detunnel_next
#undef _
	},
};

void ipv6_detunnel_counter_validate(u32 sw_if_index)
{
	ipv6_detunnel_main_t *idm = &ipv6_detunnel_main;

	if (PREDICT_FALSE(idm->counter_if_index < sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&idm->counters[IPV6_##id], sw_if_index);
	foreach_detunnel_counter
#undef _

		for (u32 i = idm->counter_if_index + 1; i <= sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&idm->counters[IPV6_##id], i);
	foreach_detunnel_counter
#undef _
		}

		idm->counter_if_index = sw_if_index;
	}
}

#endif

CLIB_MARCH_FN (ipv6_detunnel_init, clib_error_t *, vlib_main_t __clib_unused *vm)
{
	clib_warning("size: %lu %s", simd_u16_size, CLIB_STRING_MACRO(simd_u16_t));

	simd_u16(ipv6_etc_next) = simd_u16_splat(IPV6_NEXT_IPV6_ETC_DETUNNEL);
	simd_u16(ipv4_next) = simd_u16_splat(IPV6_NEXT_IPV4_DETUNNEL);
	simd_u16(ipv6_next) = simd_u16_splat(IPV6_NEXT_IPV6_DETUNNEL);
	simd_u16(ipv6_frag_next) = simd_u16_splat(IPV6_NEXT_IPV6_FRAG_DETUNNEL);
	simd_u16(gre_next) = simd_u16_splat(IPV6_NEXT_GRE_DETUNNEL);
	simd_u16(tcp_next) = simd_u16_splat(IPV6_NEXT_TCP_DETUNNEL);
	simd_u16(udp_next) = simd_u16_splat(IPV6_NEXT_UDP_DETUNNEL);
	simd_u16(failed_next) = simd_u16_splat(IPV6_NEXT_FAILED_DETUNNEL);

	return 0;
}

static clib_error_t *
ipv6_detunnel_worker_init(vlib_main_t __clib_unused *vm)
{
	ipv6_detunnel_worker_t *idw = &ipv6_detunnel_worker;
	clib_memset(idw->counters, 0, sizeof(idw->counters));
	return 0;
}

static clib_error_t *
ipv6_detunnel_init(vlib_main_t *vm)
{
	ipv6_detunnel_main_t *idm = &ipv6_detunnel_main;
	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	idm->counter_if_index = pool_elts(im->sw_interfaces);

#define _(E, n)																\
	vlib_combined_counter_main_t *cm_##n = &idm->counters[IPV6_##E];		\
	cm_##n->name = "ipv6_" #n;												\
	cm_##n->stat_segment_name = "/detunnel/ipv6/" #n;						\
	vlib_validate_combined_counter(cm_##n, idm->counter_if_index);			\
	vlib_zero_combined_counter(cm_##n, idm->counter_if_index);

	foreach_detunnel_counter
#undef _

	return CLIB_MARCH_FN_SELECT(ipv6_detunnel_init) (vm);
}

VLIB_WORKER_INIT_FUNCTION (ipv6_detunnel_worker_init);
VLIB_INIT_FUNCTION (ipv6_detunnel_init);