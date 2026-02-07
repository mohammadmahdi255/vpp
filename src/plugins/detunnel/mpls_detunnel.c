#include <vlib/vlib.h>

#include <vnet/vnet.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include "detunnel.h"
#include "vnet/mpls/packet.h"
#include "vppinfra/string.h"

#define foreach_mpls_detunnel_next								\
	_(ethernet_next, ETHERNET_DETUNNEL, "ethernet-detunnel")	\
	_(mpls_next, MPLS_DETUNNEL, "mpls-detunnel")				\
	_(ipv4_next, IPV4_DETUNNEL, "ipv4-detunnel")				\
	_(ipv6_next, IPV6_DETUNNEL, "ipv6-detunnel")				\
	_(failed_next, FAILED_DETUNNEL, "failed-detunnel")

#define foreach_mpls_protocol	\
	_(mpls_label)				\
	_(ipv4_version)				\
	_(ipv6_version)				\

#define MPLS_LABEL		0x0010
#define IPV4_VERSION	0x0040
#define IPV6_VERSION	0x0060

enum
{
#define _(var, id, name) MPLS_NEXT_##id,
	foreach_mpls_detunnel_next
#undef _
	MPLS_NEXT_N,
};

#define _(var, id, name) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_mpls_detunnel_next
#undef _

#define _(var) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_mpls_protocol
#undef _

enum
{
#define _(id, name) MPLS_##id,
	foreach_detunnel_counter
#undef _
	MPLS_COUNTER_N,
};

typedef struct
{
	// mpls_header_t eth;
} mpls_trace_t;

typedef struct
{
	u32 counter_if_index;
	vlib_counter_t cache_counters[MAX_IF_SIZE];
	vlib_combined_counter_main_t counters[MPLS_COUNTER_N];
} mpls_detunnel_main_t;

extern mpls_detunnel_main_t mpls_detunnel_main;
extern vlib_node_registration_t mpls_detunnel;

static_always_inline void
mpls_to_next(u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE next_vec = SIMD_LOAD(next + i);
		SIMD_TYPE mpls_mask_vec = (next_vec == SIMD_VEC(mpls_label));
		SIMD_TYPE ipv4_mask_vec = (next_vec == SIMD_VEC(ipv4_version));
		SIMD_TYPE ipv6_mask_vec = (next_vec == SIMD_VEC(ipv6_version));
		SIMD_TYPE failed_mask_vec = (next_vec == SIMD_VEC(invalid_protocol));

		SIMD_TYPE result = SIMD_VEC(ethernet_next) |
				(mpls_mask_vec & SIMD_VEC(mpls_next)) |
				(ipv4_mask_vec & SIMD_VEC(ipv4_next)) |
				(ipv6_mask_vec & SIMD_VEC(ipv6_next)) |
				(failed_mask_vec & SIMD_VEC(failed_next));

		SIMD_STORE(result, next + i);
	}
}

// static_always_inline void
// add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
// 		const mpls_header_t *eth, const u8 is_valid)
// {
// 	if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) && (b->flags & VLIB_BUFFER_IS_TRACED)))
// 	{
// 		mpls_trace_t *t = vlib_add_trace(vm, node, b, sizeof(mpls_trace_t));
// 		// t->eth = is_valid ? *eth : (mpls_header_t){0};
// 	}
// }

static_always_inline void
process_buffer_4x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t* b[4], u16 next[4])
{
	const u32 sw_idx0 = vnet_buffer(b[0])->sw_if_index[VLIB_RX];
	const u32 sw_idx1 = vnet_buffer(b[1])->sw_if_index[VLIB_RX];
	const u32 sw_idx2 = vnet_buffer(b[2])->sw_if_index[VLIB_RX];
	const u32 sw_idx3 = vnet_buffer(b[3])->sw_if_index[VLIB_RX];

	const u8 sw_idx_eq = sw_idx0 == sw_idx1 && sw_idx2 == sw_idx3 && sw_idx0 == sw_idx2;

	const u8 is_valid0 = vlib_buffer_has_space(b[0], sizeof(mpls_label_t));
	const u8 is_valid1 = vlib_buffer_has_space(b[1], sizeof(mpls_label_t));
	const u8 is_valid2 = vlib_buffer_has_space(b[2], sizeof(mpls_label_t));
	const u8 is_valid3 = vlib_buffer_has_space(b[3], sizeof(mpls_label_t));

	const u16 bytes0 = is_valid0 ? sizeof(mpls_label_t) : 0;
	const u16 bytes1 = is_valid1 ? sizeof(mpls_label_t) : 0;
	const u16 bytes2 = is_valid2 ? sizeof(mpls_label_t) : 0;
	const u16 bytes3 = is_valid3 ? sizeof(mpls_label_t) : 0;

	const mpls_label_t *label0 = vlib_buffer_get_current(b[0]);
	const mpls_label_t *label1 = vlib_buffer_get_current(b[1]);
	const mpls_label_t *label2 = vlib_buffer_get_current(b[2]);
	const mpls_label_t *label3 = vlib_buffer_get_current(b[3]);

	vlib_buffer_advance(b[0], bytes0);
	vlib_buffer_advance(b[1], bytes1);
	vlib_buffer_advance(b[2], bytes2);
	vlib_buffer_advance(b[3], bytes3);

	const u8 is_eos0 = *label0 & clib_host_to_net_u32(MPLS_ENTRY_EOS_BIT);
	const u8 is_eos1 = *label1 & clib_host_to_net_u32(MPLS_ENTRY_EOS_BIT);
	const u8 is_eos2 = *label2 & clib_host_to_net_u32(MPLS_ENTRY_EOS_BIT);
	const u8 is_eos3 = *label3 & clib_host_to_net_u32(MPLS_ENTRY_EOS_BIT);

	next[0] = is_valid0 ? (is_eos0 ? (*(u8 *) vlib_buffer_get_current(b[0]) & 0xF0) : MPLS_LABEL) : IP_PROTOCOL_INVALID;
	next[1] = is_valid1 ? (is_eos1 ? (*(u8 *) vlib_buffer_get_current(b[0]) & 0xF0) : MPLS_LABEL) : IP_PROTOCOL_INVALID;
	next[2] = is_valid2 ? (is_eos2 ? (*(u8 *) vlib_buffer_get_current(b[0]) & 0xF0) : MPLS_LABEL) : IP_PROTOCOL_INVALID;
	next[3] = is_valid3 ? (is_eos3 ? (*(u8 *) vlib_buffer_get_current(b[0]) & 0xF0) : MPLS_LABEL) : IP_PROTOCOL_INVALID;

	mpls_detunnel_main_t *edm = &mpls_detunnel_main;

	if (PREDICT_TRUE(sw_idx_eq))
	{
		edm->cache_counters[sw_idx0].packets += is_valid0 + is_valid1 + is_valid2 + is_valid3;
		edm->cache_counters[sw_idx0].bytes +=  bytes0 + bytes1 + bytes2 + bytes3;
	}
	else
	{
		edm->cache_counters[sw_idx0].packets += is_valid0;
		edm->cache_counters[sw_idx1].packets += is_valid1;
		edm->cache_counters[sw_idx2].packets += is_valid2;
		edm->cache_counters[sw_idx3].packets += is_valid3;
		edm->cache_counters[sw_idx0].bytes += bytes0;
		edm->cache_counters[sw_idx1].bytes += bytes1;
		edm->cache_counters[sw_idx2].bytes += bytes2;
		edm->cache_counters[sw_idx3].bytes += bytes3;
	}

	// if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
	// {
		// add_trace(vm, node, b[0], eth0, is_valid0);
		// add_trace(vm, node, b[1], eth1, is_valid1);
		// add_trace(vm, node, b[2], eth2, is_valid2);
		// add_trace(vm, node, b[3], eth3, is_valid3);
	// }
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next)
{
	mpls_detunnel_main_t *edm = &mpls_detunnel_main;
	const u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];

	const u8 is_valid = vlib_buffer_has_space(b, sizeof(mpls_label_t));
	const u16 bytes = is_valid ? sizeof(mpls_label_t) : 0;

	const mpls_label_t *label = vlib_buffer_get_current(b);
	vlib_buffer_advance(b, bytes);

	const u8 is_eos = *label & clib_host_to_net_u32(MPLS_ENTRY_EOS_BIT);
	next[0] = is_valid ? (is_eos ? (*(u8 *) vlib_buffer_get_current(b) & 0xF0) : MPLS_LABEL) : IP_PROTOCOL_INVALID;

	edm->cache_counters[sw_idx].packets += is_valid;
	edm->cache_counters[sw_idx].bytes += bytes;

	// if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
	// 	add_trace(vm, node, b, eth, is_valid);
}

VLIB_NODE_FN (mpls_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
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

	mpls_detunnel_main_t *edm = &mpls_detunnel_main;

	if (PREDICT_FALSE(edm->counter_if_index < max_sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&edm->counters[MPLS_##id], max_sw_if_index);
	foreach_detunnel_counter
#undef _

		for (u32 i = edm->counter_if_index + 1; i <= max_sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&edm->counters[MPLS_##id], i);
	foreach_detunnel_counter
#undef _
		}

		edm->counter_if_index = max_sw_if_index;
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

		process_buffer_4x(vm, node, b, next);

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
		vlib_counter_t *counter = &edm->cache_counters[sw_idx];
		vlib_increment_combined_counter(&edm->counters[MPLS_PROCESSED], vm->thread_index,
				sw_idx, counter->packets, counter->bytes);

		counter->packets = 0;
		counter->bytes = 0;
	}

	mpls_to_next(nexts, frame->n_vectors);
	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

#ifndef CLIB_MARCH_VARIANT
mpls_detunnel_main_t mpls_detunnel_main;

static u8 *format_mpls_detunnel_trace(u8 *s, va_list *args)
{
	vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
	vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
	// mpls_trace_t *t = va_arg(*args, mpls_trace_t *);
	// return format(s, "dst mac    %U\n"
	// 		"  src mac    %U\n"
	// 		"  ethertype  0x%04x",
	// 		format_mpls_address, t->eth.dst_address,
	// 		format_mpls_address, t->eth.src_address,
	// 		clib_net_to_host_u16(t->eth.type));
	return 0;
}

VLIB_REGISTER_NODE (mpls_detunnel) = {
	.name = "mpls-detunnel",
	.vector_size = sizeof(u32),
	.format_trace = format_mpls_detunnel_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = MPLS_NEXT_N,
	.next_nodes = {
#define _(var, id, name) [MPLS_NEXT_##id] = (name),
	foreach_mpls_detunnel_next
#undef _
	},
};
#endif

CLIB_MARCH_FN (mpls_detunnel_init, clib_error_t *, vlib_main_t __clib_unused *vm)
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));

	SIMD_VEC(mpls_label) = SIMD_SPLAT(MPLS_LABEL);
	SIMD_VEC(ipv4_version) = SIMD_SPLAT(IPV4_VERSION);
	SIMD_VEC(ipv6_version) = SIMD_SPLAT(IPV6_VERSION);

	SIMD_VEC(ethernet_next) = SIMD_SPLAT(MPLS_NEXT_ETHERNET_DETUNNEL);
	SIMD_VEC(mpls_next) = SIMD_SPLAT(MPLS_NEXT_MPLS_DETUNNEL);
	SIMD_VEC(ipv4_next) = SIMD_SPLAT(MPLS_NEXT_IPV4_DETUNNEL);
	SIMD_VEC(ipv6_next) = SIMD_SPLAT(MPLS_NEXT_IPV6_DETUNNEL);
	SIMD_VEC(failed_next) = SIMD_SPLAT(MPLS_NEXT_IPV6_DETUNNEL);

	return 0;
}

static clib_error_t *mpls_detunnel_init(vlib_main_t *vm)
{
	mpls_detunnel_main_t *edm = &mpls_detunnel_main;
	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	edm->counter_if_index = pool_elts(im->sw_interfaces);

#define _(E, n)																\
	vlib_combined_counter_main_t *cm_##n = &edm->counters[MPLS_##E];	\
	cm_##n->name = "mpls_" #n;											\
	cm_##n->stat_segment_name = "/detunnel/mpls/" #n;					\
	vlib_validate_combined_counter(cm_##n, edm->counter_if_index);			\
	vlib_zero_combined_counter(cm_##n, edm->counter_if_index);

	foreach_detunnel_counter
#undef _

	clib_memset(edm->cache_counters, 0, sizeof(edm->cache_counters));

	return CLIB_MARCH_FN_SELECT(mpls_detunnel_init) (vm);
}

VLIB_INIT_FUNCTION (mpls_detunnel_init);