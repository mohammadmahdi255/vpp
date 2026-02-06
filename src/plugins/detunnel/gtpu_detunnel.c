#include <stdbool.h>

#include <vlib/vlib.h>

#include <vnet/ip/ip4_packet.h>
#include <vnet/vnet.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include <gtpu/gtpu.h>

#include "detunnel.h"

#define foreach_gtpu_detunnel_next					\
	_(drop_next, DROP, "drop")						\
	_(ipv4_next, IPV4_DETUNNEL, "ipv4-detunnel")	\
	_(ipv6_next, IPV6_DETUNNEL, "ip6-drop")			\
	_(gtpu_ext_next, GTPU_EXT_DETUNNEL, "error-drop")

#define foreach_gtpu_protocol	\
	_(ipv4_version)				\
	_(ipv6_version)				\
	_(gtpu4_ext)				\
	_(gtpu6_ext)

#define IPV4_VERSION	0x0040
#define IPV6_VERSION	0x0060
#define GTPU4_EXT		0x0044
#define GTPU6_EXT		0x0064

enum
{
#define _(var, id, name) GTPU_NEXT_##id,
	foreach_gtpu_detunnel_next
#undef _
	GTPU_NEXT_N,
};

#define _(var, id, name) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_gtpu_detunnel_next
#undef _

#define _(var) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_gtpu_protocol
#undef _

enum
{
#define _(id, name) GTPU_##id,
	foreach_detunnel_counter
#undef _
	GTPU_COUNTER_N,
};

typedef struct
{
	gtpu_header_t gtpu;
	u32 sw_if_index;
} gtpu_trace_t;

typedef struct {
	u32 counter_if_index;
	vlib_counter_t cache_counters[MAX_IF_SIZE];
	vlib_combined_counter_main_t counters[GTPU_COUNTER_N];
} gtpu_detunnel_main_t;

extern gtpu_detunnel_main_t gtpu_detunnel_main;
extern vlib_node_registration_t gtpu_detunnel;

static_always_inline void
gtpu_to_next(u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE next_vec = SIMD_LOAD(next + i);
		SIMD_TYPE ipv4_mask_vec = (next_vec == SIMD_VEC(ipv4_version));
		SIMD_TYPE ipv6_mask_vec = (next_vec == SIMD_VEC(ipv6_version));
		SIMD_TYPE gtpu_ext_mask_vec = (next_vec == SIMD_VEC(gtpu4_ext)) | (next_vec == SIMD_VEC(gtpu6_ext));

		SIMD_TYPE result = SIMD_VEC(drop_next) |
				(ipv4_mask_vec & SIMD_VEC(ipv4_next)) |
				(ipv6_mask_vec & SIMD_VEC(ipv6_next)) |
				(gtpu_ext_mask_vec & SIMD_VEC(gtpu_ext_next));

		SIMD_STORE(result, next + i);
	}
}

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		const gtpu_header_t *gtpu)
{
	if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) && (b->flags & VLIB_BUFFER_IS_TRACED)))
	{
		gtpu_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
		t->gtpu = *gtpu;
		t->sw_if_index = vnet_buffer(b)->sw_if_index[VLIB_RX];
	}
}

static_always_inline void
process_buffer_4x(vlib_main_t *vm, vlib_node_runtime_t *node,
		vlib_buffer_t* b[4], u16 next[4])
{
	const u32 sw_idx0 = vnet_buffer(b[0])->sw_if_index[VLIB_RX];
	const u32 sw_idx1 = vnet_buffer(b[1])->sw_if_index[VLIB_RX];
	const u32 sw_idx2 = vnet_buffer(b[2])->sw_if_index[VLIB_RX];
	const u32 sw_idx3 = vnet_buffer(b[3])->sw_if_index[VLIB_RX];

	const u8 sw_idx_eq = sw_idx0 == sw_idx1 && sw_idx2 == sw_idx3 && sw_idx0 == sw_idx2;

	const gtpu_header_t *gtpu0 = vlib_buffer_get_current(b[0]);
	const gtpu_header_t *gtpu1 = vlib_buffer_get_current(b[1]);
	const gtpu_header_t *gtpu2 = vlib_buffer_get_current(b[2]);
	const gtpu_header_t *gtpu3 = vlib_buffer_get_current(b[3]);

	const u16 gtpu_hdr_len0 =
			sizeof(gtpu_header_t) - (((gtpu0->ver_flags & GTPU_E_S_PN_BIT) == 0) * sizeof(gtpu_ext_header_t));
	const u16 gtpu_hdr_len1 =
			sizeof(gtpu_header_t) - (((gtpu1->ver_flags & GTPU_E_S_PN_BIT) == 0) * sizeof(gtpu_ext_header_t));
	const u16 gtpu_hdr_len2 =
			sizeof(gtpu_header_t) - (((gtpu2->ver_flags & GTPU_E_S_PN_BIT) == 0) * sizeof(gtpu_ext_header_t));
	const u16 gtpu_hdr_len3 =
			sizeof(gtpu_header_t) - (((gtpu3->ver_flags & GTPU_E_S_PN_BIT) == 0) * sizeof(gtpu_ext_header_t));

	const u8 is_valid0 = vlib_buffer_has_space(b[0], gtpu_hdr_len0);
	const u8 is_valid1 = vlib_buffer_has_space(b[1], gtpu_hdr_len1);
	const u8 is_valid2 = vlib_buffer_has_space(b[2], gtpu_hdr_len2);
	const u8 is_valid3 = vlib_buffer_has_space(b[3], gtpu_hdr_len3);

	const u16 bytes0 = is_valid0 ? gtpu_hdr_len0 : 0;
	const u16 bytes1 = is_valid1 ? gtpu_hdr_len1 : 0;
	const u16 bytes2 = is_valid2 ? gtpu_hdr_len2 : 0;
	const u16 bytes3 = is_valid3 ? gtpu_hdr_len3 : 0;

	vlib_buffer_advance(b[0], bytes0);
	vlib_buffer_advance(b[1], bytes1);
	vlib_buffer_advance(b[2], bytes2);
	vlib_buffer_advance(b[3], bytes3);

	next[0] = (*(u8 *) vlib_buffer_get_current(b[0]) & 0xF0) | (gtpu0->ver_flags & GTPU_E_BIT);
	next[1] = (*(u8 *) vlib_buffer_get_current(b[1]) & 0xF0) | (gtpu0->ver_flags & GTPU_E_BIT);
	next[2] = (*(u8 *) vlib_buffer_get_current(b[2]) & 0xF0) | (gtpu0->ver_flags & GTPU_E_BIT);
	next[3] = (*(u8 *) vlib_buffer_get_current(b[3]) & 0xF0) | (gtpu0->ver_flags & GTPU_E_BIT);

	next[0] = is_valid0 ? next[0] : GTPU_INPUT_NEXT_DROP;
	next[1] = is_valid1 ? next[1] : GTPU_INPUT_NEXT_DROP;
	next[2] = is_valid2 ? next[2] : GTPU_INPUT_NEXT_DROP;
	next[3] = is_valid3 ? next[3] : GTPU_INPUT_NEXT_DROP;

	gtpu_detunnel_main_t *gdm = &gtpu_detunnel_main;

	if (PREDICT_TRUE(sw_idx_eq))
	{
		gdm->cache_counters[sw_idx0].packets += is_valid0 + is_valid1 + is_valid2 + is_valid3;
		gdm->cache_counters[sw_idx0].bytes += gtpu_hdr_len0 + gtpu_hdr_len1 + gtpu_hdr_len2 + gtpu_hdr_len3;
	}
	else
	{
		gdm->cache_counters[sw_idx0].packets += is_valid0;
		gdm->cache_counters[sw_idx1].packets += is_valid1;
		gdm->cache_counters[sw_idx2].packets += is_valid2;
		gdm->cache_counters[sw_idx3].packets += is_valid3;
		gdm->cache_counters[sw_idx0].bytes += bytes0;
		gdm->cache_counters[sw_idx1].bytes += bytes1;
		gdm->cache_counters[sw_idx2].bytes += bytes2;
		gdm->cache_counters[sw_idx3].bytes += bytes3;
	}

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
	{
		add_trace(vm, node, b[0], gtpu0);
		add_trace(vm, node, b[1], gtpu1);
		add_trace(vm, node, b[2], gtpu2);
		add_trace(vm, node, b[3], gtpu3);
	}
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next)
{
	gtpu_detunnel_main_t *gdm = &gtpu_detunnel_main;
	u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];

	const gtpu_header_t *gtpu = vlib_buffer_get_current(b);

	const u16 gtpu_hdr_len =
			sizeof(gtpu_header_t) - (((gtpu->ver_flags & GTPU_E_S_PN_BIT) == 0) * sizeof(gtpu_ext_header_t));

	const u8 is_valid = vlib_buffer_has_space(b, gtpu_hdr_len);
	vlib_buffer_advance(b, gtpu_hdr_len);

	gdm->cache_counters[sw_idx].packets += is_valid;
	gdm->cache_counters[sw_idx].bytes += gtpu_hdr_len;

	next[0] = (*(u8 *) vlib_buffer_get_current(b) & 0xF0) | (gtpu->ver_flags & GTPU_E_BIT);

	next[0] = is_valid ? next[0] : GTPU_INPUT_NEXT_DROP;

	if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
		add_trace(vm, node, b, gtpu);
}

VLIB_NODE_FN (gtpu_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
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

	gtpu_detunnel_main_t *gdm = &gtpu_detunnel_main;

	if (PREDICT_FALSE(gdm->counter_if_index < max_sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&gdm->counters[GTPU_##id], max_sw_if_index);
	foreach_detunnel_counter
#undef _

		for (u32 i = gdm->counter_if_index + 1; i <= max_sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&gdm->counters[GTPU_##id], i);
	foreach_detunnel_counter
#undef _
		}

		gdm->counter_if_index = max_sw_if_index;
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
		process_buffer_1x(vm, node, b[0], &next[0]);

		b++;
		next++;
		n_left_from--;
	}

	for (u32 sw_idx = 0; sw_idx <= max_sw_if_index; sw_idx++)
	{
		vlib_counter_t *counter = &gdm->cache_counters[sw_idx];
		vlib_increment_combined_counter(&gdm->counters[GTPU_PROCESSED], vm->thread_index,
				sw_idx, counter->packets, counter->bytes);

		counter->packets = 0;
		counter->bytes = 0;
	}

	gtpu_to_next(nexts, frame->n_vectors);

	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

#ifndef CLIB_MARCH_VARIANT
gtpu_detunnel_main_t gtpu_detunnel_main;

static u8 *format_gtpu_trace(u8 *s, va_list *args)
{
	vlib_main_t *CLIB_UNUSED(vm)   = va_arg(*args, vlib_main_t *);
	vlib_node_t *CLIB_UNUSED(node) = va_arg(*args, vlib_node_t *);
	gtpu_trace_t *t = va_arg(*args, gtpu_trace_t *);
	return format(s, "gtpu detunnel: if index %u ver_flags %u",
			t->sw_if_index, t->gtpu.ver_flags);
}

VLIB_REGISTER_NODE (gtpu_detunnel) = {
	.name = "gtpu-detunnel",
	.vector_size = sizeof(u32),
	.format_trace = format_gtpu_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = GTPU_NEXT_N,
	.next_nodes = {
#define _(var, id, name) [GTPU_NEXT_##id] = (name),
	foreach_gtpu_detunnel_next
#undef _
	},
};

#endif

CLIB_MARCH_FN (gtpu_detunnel_init, clib_error_t *, vlib_main_t *CLIB_UNUSED(vm))
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));

	SIMD_VEC(ipv4_version) = SIMD_SPLAT(IPV4_VERSION);
	SIMD_VEC(ipv6_version) = SIMD_SPLAT(IPV6_VERSION);
	SIMD_VEC(gtpu4_ext) = SIMD_SPLAT(GTPU4_EXT);
	SIMD_VEC(gtpu6_ext) = SIMD_SPLAT(GTPU6_EXT);

	SIMD_VEC(drop_next) = SIMD_SPLAT(GTPU_NEXT_DROP);
	SIMD_VEC(ipv4_next) = SIMD_SPLAT(GTPU_NEXT_IPV4_DETUNNEL);
	SIMD_VEC(ipv6_next) = SIMD_SPLAT(GTPU_NEXT_IPV6_DETUNNEL);
	SIMD_VEC(gtpu_ext_next) = SIMD_SPLAT(GTPU_NEXT_GTPU_EXT_DETUNNEL);

	return 0;
}

static clib_error_t *gtpu_detunnel_init(vlib_main_t *CLIB_UNUSED(vm))
{
	gtpu_detunnel_main_t *gdm = &gtpu_detunnel_main;
	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	gdm->counter_if_index = pool_elts(im->sw_interfaces);

#define _(E, n)																\
	vlib_combined_counter_main_t *cm_##n = &gdm->counters[GTPU_##E];	\
	cm_##n->name = "gtpu_" #n;											\
	cm_##n->stat_segment_name = "/detunnel/gtpu/" #n;					\
	vlib_validate_combined_counter(cm_##n, gdm->counter_if_index);			\
	vlib_zero_combined_counter(cm_##n, gdm->counter_if_index);

	foreach_detunnel_counter
#undef _

	clib_memset(gdm->cache_counters, 0, sizeof(gdm->cache_counters));

	return CLIB_MARCH_FN_SELECT(gtpu_detunnel_init) (vm);
}

VLIB_INIT_FUNCTION (gtpu_detunnel_init);