#include <vlib/vlib.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/vnet.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <vppinfra/string.h>

#include "detunnel.h"

#define foreach_ethernet_detunnel_next					\
	_(drop_next, DROP, "drop")							\
	_(vlan_next, VLAN_DETUNNEL, "vlan-detunnel")		\
	_(ipv4_next, IPV4_DETUNNEL, "ipv4-detunnel")		\
	_(ipv6_next, IPV6_DETUNNEL, "ipv6-detunnel")		\
	_(mpls_next, MPLS_DETUNNEL, "mpls-detunnel")		\
	_(pppoe_next, PPPOE_DETUNNEL, "pppoe-detunnel")		\
	_(ppp_next, PPP_DETUNNEL, "ppp-detunnel")			\
	_(failed_next, FAILED_DETUNNEL, "failed-detunnel")

enum
{
#define _(var, id, name) ETHERNET_NEXT_##id,
	foreach_ethernet_detunnel_next
#undef _
	ETHERNET_NEXT_N,
};

#define _(var, id, name) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_ethernet_detunnel_next
#undef _

enum
{
#define _(id, name) ETHERNET_##id,
	foreach_detunnel_counter
#undef _
	ETHERNET_COUNTER_N,
};

typedef struct
{
	ethernet_header_t eth;
} ethernet_trace_t;

typedef struct
{
	u32 counter_if_index;
	vlib_combined_counter_main_t counters[ETHERNET_COUNTER_N];
} ethernet_detunnel_main_t;

typedef struct
{
	vlib_counter_t counters[MAX_IF_SIZE];
} ethernet_detunnel_worker_t;

extern __thread ethernet_detunnel_worker_t ethernet_detunnel_worker;
extern ethernet_detunnel_main_t ethernet_detunnel_main;
extern vlib_node_registration_t ethernet_detunnel;

static_always_inline void
ethernet_to_next(u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE next_vec = SIMD_LOAD(next + i);
		SIMD_TYPE vlan_mask_vec = (next_vec == SIMD_VEC(vlan_ethertype));
		SIMD_TYPE ipv4_mask_vec = (next_vec == SIMD_VEC(ipv4_ethertype));
		SIMD_TYPE ipv6_mask_vec = (next_vec == SIMD_VEC(ipv6_ethertype));
		SIMD_TYPE mpls_mask_vec = (next_vec == SIMD_VEC(mpls_ethertype));
		SIMD_TYPE pppoe_mask_vec = (next_vec == SIMD_VEC(pppoe_session_ethertype)) |
				(next_vec == SIMD_VEC(pppoe_discovery_ethertype));
		SIMD_TYPE ppp_mask_vec = (next_vec == SIMD_VEC(ppp_ethertype));
		SIMD_TYPE failed_mask_vec = (next_vec == SIMD_VEC(invalid_ethertype));

		SIMD_TYPE result = SIMD_VEC(drop_next) |
				(vlan_mask_vec & SIMD_VEC(vlan_next)) |
				(ipv4_mask_vec & SIMD_VEC(ipv4_next)) |
				(ipv6_mask_vec & SIMD_VEC(ipv6_next)) |
				(mpls_mask_vec & SIMD_VEC(mpls_next)) |
				(pppoe_mask_vec & SIMD_VEC(pppoe_next)) |
				(ppp_mask_vec & SIMD_VEC(ppp_next)) |
				(failed_mask_vec & SIMD_VEC(failed_next));

		SIMD_STORE(result, next + i);
	}
}

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		const ethernet_header_t *eth)
{
	if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
	{
		ethernet_trace_t *t = vlib_add_trace(vm, node, b, sizeof(ethernet_trace_t));
		t->eth = *eth;
	}
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next, u8 is_trace)
{
	ethernet_detunnel_worker_t *edw = &ethernet_detunnel_worker;
	const u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];
	const ethernet_header_t *eth = vlib_buffer_get_current(b);

	if (PREDICT_FALSE(!vlib_buffer_has_space(b, sizeof(ethernet_header_t))))
	{
		next[0] = ETHERNET_TYPE_INVALID;
		goto trace;
	}

	vlib_buffer_advance(b, sizeof(ethernet_header_t));
	edw->counters[sw_idx].packets++;
	edw->counters[sw_idx].bytes += sizeof(ethernet_header_t);
	next[0] = eth->type;

trace:
	if (is_trace)
		add_trace(vm, node, b, eth);
}

static_always_inline u64
ethernet_detunnel_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_trace)
{
	vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
	u16 nexts[VLIB_FRAME_SIZE];
	vlib_buffer_t **b = bufs;
	u16 *next = nexts;

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

	ethernet_detunnel_main_t *edm = &ethernet_detunnel_main;
	ethernet_detunnel_worker_t *edw = &ethernet_detunnel_worker;

	for (u32 sw_idx = 0; sw_idx <= edm->counter_if_index; sw_idx++)
	{
		vlib_counter_t *counter = &edw->counters[sw_idx];
		vlib_increment_combined_counter(&edm->counters[ETHERNET_PROCESSED], vm->thread_index,
				sw_idx, counter->packets, counter->bytes);

		counter->packets = 0;
		counter->bytes = 0;
	}

	ethernet_to_next(nexts, frame->n_vectors);
	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

VLIB_NODE_FN (ethernet_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	return ethernet_detunnel_inline(vm, node, frame, node->flags & VLIB_NODE_FLAG_TRACE);
}

#ifndef CLIB_MARCH_VARIANT
__thread ethernet_detunnel_worker_t ethernet_detunnel_worker;
ethernet_detunnel_main_t ethernet_detunnel_main;

static u8 *format_ethernet_detunnel_trace(u8 *s, va_list *args)
{
	vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
	vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
	ethernet_trace_t *t = va_arg(*args, ethernet_trace_t *);
	return format(s, "dst mac    %U\n"
			"  src mac    %U\n"
			"  ethertype  0x%04x",
			format_ethernet_address, t->eth.dst_address,
			format_ethernet_address, t->eth.src_address,
			clib_net_to_host_u16(t->eth.type));
}

VLIB_REGISTER_NODE (ethernet_detunnel) = {
	.name = "ethernet-detunnel",
	.vector_size = sizeof(u32),
	.format_trace = format_ethernet_detunnel_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = ETHERNET_NEXT_N,
	.next_nodes = {
#define _(var, id, name) [ETHERNET_NEXT_##id] = (name),
	foreach_ethernet_detunnel_next
#undef _
	},
};

void ethernet_detunnel_counter_validate(u32 sw_if_index)
{
	ethernet_detunnel_main_t *edm = &ethernet_detunnel_main;

	clib_warning("interface max index %u", sw_if_index);

	if (PREDICT_FALSE(edm->counter_if_index < sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&edm->counters[ETHERNET_##id], sw_if_index);
	foreach_detunnel_counter
#undef _

		for (u32 i = edm->counter_if_index + 1; i <= sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&edm->counters[ETHERNET_##id], i);
	foreach_detunnel_counter
#undef _
		}

		edm->counter_if_index = sw_if_index;
	}
}

#endif

CLIB_MARCH_FN (ethernet_detunnel_init, clib_error_t *, vlib_main_t __clib_unused *vm)
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));

	SIMD_VEC(drop_next) = SIMD_SPLAT(ETHERNET_NEXT_DROP);
	SIMD_VEC(vlan_next) = SIMD_SPLAT(ETHERNET_NEXT_VLAN_DETUNNEL);
	SIMD_VEC(ipv4_next) = SIMD_SPLAT(ETHERNET_NEXT_IPV4_DETUNNEL);
	SIMD_VEC(ipv6_next) = SIMD_SPLAT(ETHERNET_NEXT_IPV6_DETUNNEL);
	SIMD_VEC(mpls_next) = SIMD_SPLAT(ETHERNET_NEXT_MPLS_DETUNNEL);
	SIMD_VEC(pppoe_next) = SIMD_SPLAT(ETHERNET_NEXT_PPPOE_DETUNNEL);
	SIMD_VEC(ppp_next) = SIMD_SPLAT(ETHERNET_NEXT_PPP_DETUNNEL);
	SIMD_VEC(failed_next) = SIMD_SPLAT(ETHERNET_NEXT_FAILED_DETUNNEL);

	return 0;
}

static clib_error_t *
ethernet_detunnel_worker_init(vlib_main_t __clib_unused *vm)
{
	ethernet_detunnel_worker_t *edw = &ethernet_detunnel_worker;
	clib_memset(edw->counters, 0, sizeof(edw->counters));
	return 0;
}

static clib_error_t *
ethernet_detunnel_init(vlib_main_t *vm)
{
	ethernet_detunnel_main_t *edm = &ethernet_detunnel_main;
	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	edm->counter_if_index = pool_elts(im->sw_interfaces);

#define _(E, n)																\
	vlib_combined_counter_main_t *cm_##n = &edm->counters[ETHERNET_##E];	\
	cm_##n->name = "ethernet_" #n;											\
	cm_##n->stat_segment_name = "/detunnel/ethernet/" #n;					\
	vlib_validate_combined_counter(cm_##n, edm->counter_if_index);			\
	vlib_zero_combined_counter(cm_##n, edm->counter_if_index);

	foreach_detunnel_counter
#undef _

	return CLIB_MARCH_FN_SELECT(ethernet_detunnel_init) (vm);
}

VLIB_WORKER_INIT_FUNCTION (ethernet_detunnel_worker_init);

VLIB_INIT_FUNCTION (ethernet_detunnel_init);

VNET_FEATURE_INIT (ethernet_detunnel_input, static) = {
	.arc_name = "device-input",
	.node_name = "ethernet-detunnel",
	.runs_before = VNET_FEATURES("ethernet-input"),
};