#include <vlib/vlib.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/vnet.h>

#include <vppinfra/clib.h>

#include <pppoe/pppoe.h>

#include "detunnel.h"

#define foreach_pppoe_detunnel_next						\
	_(drop_next, DROP, "drop")							\
	_(ipv4_next, IPV4_DETUNNEL, "ipv4-detunnel")		\
	_(ipv6_next, IPV6_DETUNNEL, "ipv6-detunnel")		\
	_(failed_next, FAILED_DETUNNEL, "failed-detunnel")

enum
{
#define _(var, id, name) PPPOE_NEXT_##id,
	foreach_pppoe_detunnel_next
#undef _
	PPPOE_NEXT_N,
};

#define _(var, id, name) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_pppoe_detunnel_next
#undef _

enum
{
#define _(id, name) PPPOE_##id,
	foreach_detunnel_counter
#undef _
	PPPOE_COUNTER_N,
};

typedef struct
{
	pppoe_header_t pppoe;
} pppoe_trace_t;

typedef struct
{
	u32 counter_if_index;
	vlib_counter_t cache_counters[MAX_IF_SIZE];
	vlib_combined_counter_main_t counters[PPPOE_COUNTER_N];
} pppoe_detunnel_main_t;

extern pppoe_detunnel_main_t pppoe_detunnel_main;

static_always_inline void
pppoe_to_next(u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE next_vec = SIMD_LOAD(next + i);
		SIMD_TYPE ipv4_mask_vec = (next_vec == SIMD_VEC(ipv4_ppp_protocol));
		SIMD_TYPE ipv6_mask_vec = (next_vec == SIMD_VEC(ipv6_ppp_protocol));
		SIMD_TYPE failed_mask_vec = (next_vec == SIMD_VEC(invalid_ppp_protocol));

		SIMD_TYPE result = SIMD_VEC(drop_next) |
				(ipv4_mask_vec & SIMD_VEC(ipv4_next)) |
				(ipv6_mask_vec & SIMD_VEC(ipv6_next)) |
				(failed_mask_vec & SIMD_VEC(failed_next));

		SIMD_STORE(result, next + i);
	}
}

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		const pppoe_header_t *pppoe)
{
	if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) && (b->flags & VLIB_BUFFER_IS_TRACED)))
	{
		pppoe_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
		t->pppoe = *pppoe;
	}
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next)
{
	pppoe_detunnel_main_t *vdm = &pppoe_detunnel_main;
	const u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];

	const pppoe_header_t *pppoe = vlib_buffer_get_current(b);

	if (PREDICT_FALSE(!vlib_buffer_has_space(b, sizeof(pppoe_header_t))))
	{
		next[0] = PPP_PROTOCOL_INVALID;
		goto trace;
	}

	vlib_buffer_advance(b, sizeof(pppoe_header_t));
	vdm->cache_counters[sw_idx].packets++;
	vdm->cache_counters[sw_idx].bytes += sizeof(pppoe_header_t);
	next[0] = pppoe->ppp_proto;

trace:
	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
		add_trace(vm, node, b, pppoe);
}

VLIB_NODE_FN (pppoe_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
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

	pppoe_detunnel_main_t *vdm = &pppoe_detunnel_main;

	if (PREDICT_FALSE(vdm->counter_if_index < max_sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&vdm->counters[PPPOE_##id], max_sw_if_index);
	foreach_detunnel_counter
#undef _

		for (u32 i = vdm->counter_if_index + 1; i <= max_sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&vdm->counters[PPPOE_##id], i);
	foreach_detunnel_counter
#undef _
		}

		vdm->counter_if_index = max_sw_if_index;
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

		process_buffer_1x(vm, node, b[0], &next[0]);
		process_buffer_1x(vm, node, b[1], &next[1]);
		process_buffer_1x(vm, node, b[2], &next[2]);
		process_buffer_1x(vm, node, b[3], &next[3]);

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
		vlib_counter_t *counter = &vdm->cache_counters[sw_idx];
		vlib_increment_combined_counter(&vdm->counters[PPPOE_PROCESSED], vm->thread_index,
				sw_idx, counter->packets, counter->bytes);

		counter->packets = 0;
		counter->bytes = 0;
	}

	pppoe_to_next(nexts, frame->n_vectors);
	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

#ifndef CLIB_MARCH_VARIANT
pppoe_detunnel_main_t pppoe_detunnel_main;

static u8 *format_pppoe_trace(u8 *s, va_list *args)
{
	vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
	vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
	pppoe_trace_t *t = va_arg(*args, pppoe_trace_t *);
	return format(s, "ver_type   0x%02x\n"
			"  code             0x%02x\n"
			"  session id       0x%04x\n"
			"  payload       	%u\n"
			"  protocol       	0x%04x",
			t->pppoe.ver_type,
			t->pppoe.code,
			t->pppoe.session_id,
			t->pppoe.length);
}

/* Register node */
VLIB_REGISTER_NODE (pppoe_detunnel) = {
	.name = "pppoe-detunnel",
	.vector_size = sizeof(u32),
	.format_trace = format_pppoe_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = PPPOE_NEXT_N,
	.next_nodes = {
#define _(var, id, name) [PPPOE_NEXT_##id] = (name),
	foreach_pppoe_detunnel_next
#undef _
	},
};
#endif

CLIB_MARCH_FN (pppoe_detunnel_init, clib_error_t *, vlib_main_t __clib_unused *vm)
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));

	SIMD_VEC(drop_next) = SIMD_SPLAT(PPPOE_NEXT_DROP);
	SIMD_VEC(ipv4_next) = SIMD_SPLAT(PPPOE_NEXT_IPV4_DETUNNEL);
	SIMD_VEC(ipv6_next) = SIMD_SPLAT(PPPOE_NEXT_IPV6_DETUNNEL);
	SIMD_VEC(failed_next) = SIMD_SPLAT(PPPOE_NEXT_FAILED_DETUNNEL);

	return 0;
}

static clib_error_t *pppoe_detunnel_init(vlib_main_t *vm)
{
	pppoe_detunnel_main_t *vdm = &pppoe_detunnel_main;
	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	vdm->counter_if_index = pool_elts(im->sw_interfaces);

#define _(E, n)																\
	vlib_combined_counter_main_t *cm_##n = &vdm->counters[PPPOE_##E];		\
	cm_##n->name = "pppoe_" #n;												\
	cm_##n->stat_segment_name = "/detunnel/pppoe/" #n;						\
	vlib_validate_combined_counter(cm_##n, vdm->counter_if_index);			\
	vlib_zero_combined_counter(cm_##n, vdm->counter_if_index);

	foreach_detunnel_counter
#undef _

	clib_memset(vdm->cache_counters, 0, sizeof(vdm->cache_counters));

	return CLIB_MARCH_FN_SELECT(pppoe_detunnel_init) (vm);
}

VLIB_INIT_FUNCTION (pppoe_detunnel_init);
