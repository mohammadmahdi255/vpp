#include <vlib/vlib.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/vnet.h>

#include <vppinfra/clib.h>

#include <ppp/ppp.h>

#include "detunnel.h"

#define foreach_ppp_detunnel_next						\
	_(drop_next, DROP, "drop")							\
	_(ipv4_next, IPV4_DETUNNEL, "ipv4-detunnel")		\
	_(ipv6_next, IPV6_DETUNNEL, "ipv6-detunnel")		\
	_(failed_next, FAILED_DETUNNEL, "failed-detunnel")

enum
{
#define _(var, id, name) PPP_NEXT_##id,
	foreach_ppp_detunnel_next
#undef _
	PPP_NEXT_N,
};

#define _(var, id, name) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_ppp_detunnel_next
#undef _

enum
{
#define _(id, name) PPP_##id,
	foreach_detunnel_counter
#undef _
	PPP_COUNTER_N,
};

#define PPP_COMPRESSED_SIGNATURE	0x01

typedef struct
{
	ppp_header_t ppp;
} ppp_trace_t;

typedef struct
{
	u32 counter_if_index;
	vlib_counter_t cache_counters[MAX_IF_SIZE];
	vlib_combined_counter_main_t counters[PPP_COUNTER_N];
} ppp_detunnel_main_t;

extern ppp_detunnel_main_t ppp_detunnel_main;

static_always_inline void
ppp_to_next(u16 *next, u16 len)
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
		const ppp_header_t *ppp)
{
	if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
	{
		ppp_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
		t->ppp = *ppp;
	}
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next, u8 is_trace)
{
	ppp_detunnel_main_t *pdm = &ppp_detunnel_main;
	const u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];

	const u8 *data = vlib_buffer_get_current(b);
	u16 offset = 0;

	if (PREDICT_FALSE(!vlib_buffer_has_space(b, sizeof(ppp_header_t))))
	{
		next[0] = PPP_PROTOCOL_INVALID;
		goto trace;
	}

	if (data[0] == 0xFF && data[1] == 0x03)
	{
		offset = sizeof(u16);
	}

	if (data[offset] & PPP_COMPRESSED_SIGNATURE)
	{
		offset += sizeof(u8);
		next[0] = data[offset] << clib_arch_is_little_endian * 8;
	}
	else
	{
		offset += sizeof(u16);
		next[0] = *(u16 *) (data + offset);
	}

	vlib_buffer_advance(b, offset);
	pdm->cache_counters[sw_idx].packets++;
	pdm->cache_counters[sw_idx].bytes += offset;

trace:
	if (is_trace)
		add_trace(vm, node, b, (ppp_header_t *) data);
}

static_always_inline u64
ppp_detunnel_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_trace)
{
	vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
	u16 nexts[VLIB_FRAME_SIZE];
	vlib_buffer_t **b = bufs;
	u16 *next = nexts;

	u32 *from = vlib_frame_vector_args(frame);
	u32 n_left_from = frame->n_vectors;

	vlib_get_buffers(vm, from, bufs, n_left_from);

	ppp_detunnel_main_t *pdm = &ppp_detunnel_main;

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

	for (u32 sw_idx = 0; sw_idx <= pdm->counter_if_index; sw_idx++)
	{
		vlib_counter_t *counter = &pdm->cache_counters[sw_idx];
		vlib_increment_combined_counter(&pdm->counters[PPP_PROCESSED], vm->thread_index,
				sw_idx, counter->packets, counter->bytes);

		counter->packets = 0;
		counter->bytes = 0;
	}

	ppp_to_next(nexts, frame->n_vectors);
	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

VLIB_NODE_FN (ppp_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	return ppp_detunnel_inline(vm, node, frame, node->flags & VLIB_NODE_FLAG_TRACE);
}

#ifndef CLIB_MARCH_VARIANT
ppp_detunnel_main_t ppp_detunnel_main;

static u8 *format_ppp_trace(u8 *s, va_list *args)
{
	vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
	vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
	ppp_trace_t *t = va_arg(*args, ppp_trace_t *);
	return format(s, "address   0x%02x\n"
			"  control   0x%02x\n"
			"  protocol  0x%04x",
			t->ppp.address,
			t->ppp.control,
			t->ppp.protocol);
}

/* Register node */
VLIB_REGISTER_NODE (ppp_detunnel) = {
	.name = "ppp-detunnel",
	.vector_size = sizeof(u32),
	.format_trace = format_ppp_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = PPP_NEXT_N,
	.next_nodes = {
#define _(var, id, name) [PPP_NEXT_##id] = (name),
	foreach_ppp_detunnel_next
#undef _
	},
};

void ppp_detunnel_counter_validate(u32 sw_if_index)
{
	ppp_detunnel_main_t *pdm = &ppp_detunnel_main;

	clib_warning("interface max index %u", sw_if_index);

	if (PREDICT_FALSE(pdm->counter_if_index < sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&pdm->counters[PPP_##id], sw_if_index);
	foreach_detunnel_counter
#undef _

		for (u32 i = pdm->counter_if_index + 1; i <= sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&pdm->counters[PPP_##id], i);
	foreach_detunnel_counter
#undef _
		}

		pdm->counter_if_index = sw_if_index;
	}
}

#endif

CLIB_MARCH_FN (ppp_detunnel_init, clib_error_t *, vlib_main_t __clib_unused *vm)
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));

	SIMD_VEC(drop_next) = SIMD_SPLAT(PPP_NEXT_DROP);
	SIMD_VEC(ipv4_next) = SIMD_SPLAT(PPP_NEXT_IPV4_DETUNNEL);
	SIMD_VEC(ipv6_next) = SIMD_SPLAT(PPP_NEXT_IPV6_DETUNNEL);
	SIMD_VEC(failed_next) = SIMD_SPLAT(PPP_NEXT_FAILED_DETUNNEL);

	return 0;
}

static clib_error_t *ppp_detunnel_init(vlib_main_t *vm)
{
	ppp_detunnel_main_t *pdm = &ppp_detunnel_main;
	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	pdm->counter_if_index = pool_elts(im->sw_interfaces);

#define _(E, n)																\
	vlib_combined_counter_main_t *cm_##n = &pdm->counters[PPP_##E];		\
	cm_##n->name = "ppp_" #n;												\
	cm_##n->stat_segment_name = "/detunnel/ppp/" #n;						\
	vlib_validate_combined_counter(cm_##n, pdm->counter_if_index);			\
	vlib_zero_combined_counter(cm_##n, pdm->counter_if_index);

	foreach_detunnel_counter
#undef _

	clib_memset(pdm->cache_counters, 0, sizeof(pdm->cache_counters));

	return CLIB_MARCH_FN_SELECT(ppp_detunnel_init) (vm);
}

VLIB_INIT_FUNCTION (ppp_detunnel_init);
