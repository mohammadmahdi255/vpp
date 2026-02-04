#include <stdbool.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include "detunnel.h"
#include "vnet/ip/ip4_packet.h"
#include "vnet/ip/ip_packet.h"

#define foreach_ipv4_detunnel_next					\
	_(drop_next, DROP, "drop")						\
	_(ipv4_next, IPV4_DETUNNEL, "ipv4-detunnel")	\
	_(ipv6_next, IPV6_DETUNNEL, "ip6-drop")			\
	_(udp_next, UDP_DETUNNEL, "udp-detunnel")

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
	u32 sw_if_index;
} ip4_trace_t;

typedef struct {
	u32 counter_if_index;
	vlib_cache_counter_t cache_counters[MAX_IF_SIZE][IPV4_COUNTER_N];
	vlib_combined_counter_main_t counters[IPV4_COUNTER_N];
} ipv4_detunnel_main_t;

extern ipv4_detunnel_main_t ipv4_detunnel_main;
extern vlib_node_registration_t ipv4_detunnel;

static_always_inline void
ipv4_to_next(u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE ip_protocol_vec = SIMD_LOAD(next + i);
		SIMD_TYPE ipv4_mask_vec = (ip_protocol_vec == SIMD_VEC(ipv4_protocol));
		SIMD_TYPE ipv6_mask_vec = (ip_protocol_vec == SIMD_VEC(ipv6_protocol));
		SIMD_TYPE udp_mask_vec = (ip_protocol_vec == SIMD_VEC(udp_protocol));

		SIMD_TYPE result = SIMD_VEC(drop_next) |
				(ipv4_mask_vec & SIMD_VEC(ipv4_next)) |
				(ipv6_mask_vec & SIMD_VEC(ipv6_next)) |
				(udp_mask_vec & SIMD_VEC(udp_next));

		SIMD_STORE(result, next + i);
	}
}

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		const ip4_header_t *ip4)
{
	if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) && (b->flags & VLIB_BUFFER_IS_TRACED)))
	{
		ip4_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
		t->ip4 = *ip4;
		t->sw_if_index = vnet_buffer(b)->sw_if_index[VLIB_RX];
	}
}

static_always_inline bool
process_buffer_4x(vlib_main_t *vm, vlib_node_runtime_t *node,
		vlib_buffer_t* b[4], u16 next[4])
{
	ipv4_detunnel_main_t *idm = &ipv4_detunnel_main;

	const u32 sw_idx0 = vnet_buffer(b[0])->sw_if_index[VLIB_RX];
	const u32 sw_idx1 = vnet_buffer(b[1])->sw_if_index[VLIB_RX];
	const u32 sw_idx2 = vnet_buffer(b[2])->sw_if_index[VLIB_RX];
	const u32 sw_idx3 = vnet_buffer(b[3])->sw_if_index[VLIB_RX];

	const ip4_header_t *ip0 = vlib_buffer_get_current(b[0]);
	const ip4_header_t *ip1 = vlib_buffer_get_current(b[1]);
	const ip4_header_t *ip2 = vlib_buffer_get_current(b[2]);
	const ip4_header_t *ip3 = vlib_buffer_get_current(b[3]);

	const u16 ip4_hdr_len0 = ip4_header_bytes(ip0);
	const u16 ip4_hdr_len1 = ip4_header_bytes(ip1);
	const u16 ip4_hdr_len2 = ip4_header_bytes(ip2);
	const u16 ip4_hdr_len3 = ip4_header_bytes(ip3);

	u8 error = 0;

	error |= ip4_hdr_len0 < sizeof(ip4_header_t);
	error |= ip4_hdr_len1 < sizeof(ip4_header_t);
	error |= ip4_hdr_len2 < sizeof(ip4_header_t);
	error |= ip4_hdr_len3 < sizeof(ip4_header_t);

	const u16 len0 = b[0]->current_length;
	const u16 len1 = b[1]->current_length;
	const u16 len2 = b[2]->current_length;
	const u16 len3 = b[3]->current_length;

	const u16 ip4_len0 = clib_net_to_host_u16(ip0->length);
	const u16 ip4_len1 = clib_net_to_host_u16(ip1->length);
	const u16 ip4_len2 = clib_net_to_host_u16(ip2->length);
	const u16 ip4_len3 = clib_net_to_host_u16(ip3->length);

	i32 ip4_pad_len0 = len0 - ip4_len0;
	i32 ip4_pad_len1 = len1 - ip4_len1;
	i32 ip4_pad_len2 = len2 - ip4_len2;
	i32 ip4_pad_len3 = len3 - ip4_len3;

	error |= ip4_pad_len0 < 0;
	error |= ip4_pad_len1 < 0;
	error |= ip4_pad_len2 < 0;
	error |= ip4_pad_len3 < 0;

	if (PREDICT_FALSE(error))
		return false;

	vlib_buffer_advance(b[0], ip4_hdr_len0);
	vlib_buffer_advance(b[1], ip4_hdr_len1);
	vlib_buffer_advance(b[2], ip4_hdr_len2);
	vlib_buffer_advance(b[3], ip4_hdr_len3);

	b[0]->current_length -= ip4_pad_len0;
	b[1]->current_length -= ip4_pad_len1;
	b[2]->current_length -= ip4_pad_len2;
	b[3]->current_length -= ip4_pad_len3;

	next[0] = ip0->protocol;
	next[1] = ip1->protocol;
	next[2] = ip2->protocol;
	next[3] = ip3->protocol;

	idm->cache_counters[sw_idx0][IPV4_TOTAL].packets++;
	idm->cache_counters[sw_idx0][IPV4_TOTAL].bytes += len0;
	idm->cache_counters[sw_idx0][IPV4_PROCESSED].packets++;
	idm->cache_counters[sw_idx0][IPV4_PROCESSED].bytes += ip4_hdr_len0 + ip4_pad_len0;
	idm->cache_counters[sw_idx1][IPV4_TOTAL].packets++;
	idm->cache_counters[sw_idx1][IPV4_TOTAL].bytes += len1;
	idm->cache_counters[sw_idx1][IPV4_PROCESSED].packets++;
	idm->cache_counters[sw_idx1][IPV4_PROCESSED].bytes += ip4_hdr_len1 + ip4_pad_len1;
	idm->cache_counters[sw_idx2][IPV4_TOTAL].packets++;
	idm->cache_counters[sw_idx2][IPV4_TOTAL].bytes += len2;
	idm->cache_counters[sw_idx2][IPV4_PROCESSED].packets++;
	idm->cache_counters[sw_idx2][IPV4_PROCESSED].bytes += ip4_hdr_len2 + ip4_pad_len2;
	idm->cache_counters[sw_idx3][IPV4_TOTAL].packets++;
	idm->cache_counters[sw_idx3][IPV4_TOTAL].bytes += len3;
	idm->cache_counters[sw_idx3][IPV4_PROCESSED].packets++;
	idm->cache_counters[sw_idx3][IPV4_PROCESSED].bytes += ip4_hdr_len3 + ip4_pad_len3;

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
	{
		add_trace(vm, node, b[0], ip0);
		add_trace(vm, node, b[1], ip1);
		add_trace(vm, node, b[2], ip2);
		add_trace(vm, node, b[3], ip3);
	}

	return true;
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next)
{
	ipv4_detunnel_main_t *idm = &ipv4_detunnel_main;
	u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];

	idm->cache_counters[sw_idx][IPV4_TOTAL].packets++;
	idm->cache_counters[sw_idx][IPV4_TOTAL].bytes += b->current_length;

	const ip4_header_t *ip4 = vlib_buffer_get_current(b);
	const u16 ip4_hdr_len = ip4_header_bytes(ip4);
	const u16 ip4_len = clib_net_to_host_u16(ip4->length);
	const i32 ip4_pad_len = b->current_length - ip4_len;

	if (PREDICT_FALSE(ip4_hdr_len < sizeof(ip4_header_t) || ip4_pad_len < 0))
	{
		idm->cache_counters[sw_idx][IPV4_FAILED].packets++;
		idm->cache_counters[sw_idx][IPV4_FAILED].bytes += b->current_length;
		next[0] = IPV4_NEXT_DROP;
		return;
	}

	b->current_length -= ip4_pad_len;
	vlib_buffer_advance(b, ip4_hdr_len);

	idm->cache_counters[sw_idx][IPV4_PROCESSED].packets++;
	idm->cache_counters[sw_idx][IPV4_PROCESSED].bytes += ip4_hdr_len + ip4_pad_len;

	if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
		add_trace(vm, node, b, ip4);

	next[0] = ip4->protocol;
}

VLIB_NODE_FN (ipv4_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
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

	ipv4_detunnel_main_t *idm = &ipv4_detunnel_main;

	if (PREDICT_FALSE(idm->counter_if_index < max_sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&idm->counters[IPV4_##id], max_sw_if_index);
	foreach_detunnel_counter
#undef _

		for (u32 i = idm->counter_if_index + 1; i <= max_sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&idm->counters[IPV4_##id], i);
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

	for (u32 sw_idx = 0; sw_idx <= max_sw_if_index; sw_idx++)
	{
		vlib_cache_counter_t *counter = idm->cache_counters[sw_idx];
		vlib_increment_combined_counter(&idm->counters[IPV4_TOTAL], vm->thread_index,
				sw_idx, counter[IPV4_TOTAL].packets, counter[IPV4_TOTAL].bytes);
		vlib_increment_combined_counter(&idm->counters[IPV4_PROCESSED], vm->thread_index,
				sw_idx, counter[IPV4_PROCESSED].packets, counter[IPV4_PROCESSED].bytes);
		vlib_increment_combined_counter(&idm->counters[IPV4_FAILED], vm->thread_index,
				sw_idx, counter[IPV4_FAILED].packets, counter[IPV4_FAILED].bytes);

		counter[IPV4_TOTAL].packets = 0;
		counter[IPV4_TOTAL].bytes = 0;
		counter[IPV4_PROCESSED].packets = 0;
		counter[IPV4_PROCESSED].bytes = 0;
		counter[IPV4_FAILED].packets = 0;
		counter[IPV4_FAILED].bytes = 0;
	}

	ipv4_to_next(nexts, frame->n_vectors);
	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

#ifndef CLIB_MARCH_VARIANT
ipv4_detunnel_main_t ipv4_detunnel_main;

static u8 *format_ipv4_trace(u8 *s, va_list *args)
{
	vlib_main_t *CLIB_UNUSED(vm)   = va_arg(*args, vlib_main_t *);
	vlib_node_t *CLIB_UNUSED(node) = va_arg(*args, vlib_node_t *);
	ip4_trace_t *t = va_arg(*args, ip4_trace_t *);
	return format(s, "ipv4 detunnel: if index %u protocol %u checksum 0x%04x",
			t->sw_if_index, t->ip4.protocol, t->ip4.checksum);
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

#endif

CLIB_MARCH_FN (ipv4_detunnel_init, clib_error_t *, vlib_main_t *CLIB_UNUSED(vm))
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));

	SIMD_VEC(drop_next) = SIMD_SPLAT(IPV4_NEXT_DROP);
	SIMD_VEC(ipv4_next) = SIMD_SPLAT(IPV4_NEXT_IPV4_DETUNNEL);
	SIMD_VEC(ipv6_next) = SIMD_SPLAT(IPV4_NEXT_IPV6_DETUNNEL);
	SIMD_VEC(udp_next) = SIMD_SPLAT(IPV4_NEXT_UDP_DETUNNEL);

	return 0;
}

static clib_error_t *ipv4_detunnel_init(vlib_main_t *CLIB_UNUSED(vm))
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

	clib_memset(idm->cache_counters, 0, sizeof(idm->cache_counters));

	return CLIB_MARCH_FN_SELECT(ipv4_detunnel_init) (vm);
}

VLIB_INIT_FUNCTION (ipv4_detunnel_init);