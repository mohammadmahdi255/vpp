#include <stdbool.h>

#include <vlib/vlib.h>

#include <vnet/ip/ip4_packet.h>
#include <vnet/vnet.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include <gtpu/gtpu.h>

#include "detunnel.h"

#define foreach_gtpu_detunnel_next									\
	_(detunnel_output_next, DETUNNEL_OUTPUT, "detunnel-output")		\
	_(ipv4_next, IPV4_DETUNNEL, "ipv4-detunnel")					\
	_(ipv6_next, IPV6_DETUNNEL, "ipv6-detunnel")					\
    _(failed_next, FAILED_DETUNNEL, "failed-detunnel")

#define foreach_gtpu_protocol	\
	_(ipv4_version)				\
	_(ipv6_version)

#define IPV4_VERSION	0x0040
#define IPV6_VERSION	0x0060

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
} gtpu_trace_t;

typedef struct {
	u32 counter_if_index;
	vlib_combined_counter_main_t counters[GTPU_COUNTER_N];
} gtpu_detunnel_main_t;

typedef struct
{
	vlib_counter_t counters[MAX_IF_SIZE];
} gtpu_detunnel_worker_t;

extern __thread gtpu_detunnel_worker_t gtpu_detunnel_worker;
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
		SIMD_TYPE failed_mask_vec = (next_vec == SIMD_VEC(invalid_protocol));

		SIMD_TYPE result = SIMD_VEC(detunnel_output_next) |
				(ipv4_mask_vec & SIMD_VEC(ipv4_next)) |
				(ipv6_mask_vec & SIMD_VEC(ipv6_next)) |
                (failed_mask_vec & SIMD_VEC(failed_next));

		SIMD_STORE(result, next + i);
	}
}

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		const gtpu_header_t *gtpu)
{
	if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
	{
		gtpu_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
		t->gtpu = *gtpu;
	}
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next, u8 is_trace)
{
	gtpu_detunnel_worker_t *gdw = &gtpu_detunnel_worker;
	u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];

	const gtpu_header_t *gtpu = vlib_buffer_get_current(b);

	u16 gtpu_hdr_len =
			sizeof(gtpu_header_t) - (((gtpu->ver_flags & GTPU_E_S_PN_BIT) == 0) * sizeof(gtpu_ext_header_t));

	if (PREDICT_FALSE(!vlib_buffer_has_space(b, gtpu_hdr_len)))
	{
		next[0] = IP_PROTOCOL_INVALID;
		goto trace;
	}

	if (gtpu->ver_flags & GTPU_E_BIT) {

		gtpu_ext_header_t *ext = (gtpu_ext_header_t *) &gtpu->next_ext_type;

		while (ext->type)
		{
			gtpu_hdr_len += ext->len * sizeof(gtpu_ext_header_t);

			if (PREDICT_FALSE(ext->len == 0 || !vlib_buffer_has_space(b, gtpu_hdr_len)))
			{
				next[0] = IP_PROTOCOL_INVALID;
				goto trace;
			}

			ext += ext->len;
		}
	}

	vlib_buffer_advance(b, gtpu_hdr_len);
	gdw->counters[sw_idx].packets++;
	gdw->counters[sw_idx].bytes += gtpu_hdr_len;
	next[0] = (*(u8 *) vlib_buffer_get_current(b) & 0xF0);

trace:
	if (is_trace)
		add_trace(vm, node, b, gtpu);
}

static_always_inline u64
gtpu_detunnel_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_trace)
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

	gtpu_detunnel_main_t *gdm = &gtpu_detunnel_main;
	gtpu_detunnel_worker_t *gdw = &gtpu_detunnel_worker;

	for (u32 sw_idx = 0; sw_idx <= gdm->counter_if_index; sw_idx++)
	{
		vlib_counter_t *counter = &gdw->counters[sw_idx];
		vlib_increment_combined_counter(&gdm->counters[GTPU_PROCESSED], vm->thread_index,
				sw_idx, counter->packets, counter->bytes);

		counter->packets = 0;
		counter->bytes = 0;
	}

	gtpu_to_next(nexts, frame->n_vectors);
	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

VLIB_NODE_FN (gtpu_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	return gtpu_detunnel_inline(vm, node, frame, node->flags & VLIB_NODE_FLAG_TRACE);
}

#ifndef CLIB_MARCH_VARIANT
__thread gtpu_detunnel_worker_t gtpu_detunnel_worker;
gtpu_detunnel_main_t gtpu_detunnel_main;

static u8 *format_gtpu_trace(u8 *s, va_list *args)
{
	vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
	vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
	gtpu_trace_t *t = va_arg(*args, gtpu_trace_t *);
	return format(s,"teid %u\n"
			"  ver_flags %u",
			t->gtpu.teid,
			t->gtpu.ver_flags);
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

void gtpu_detunnel_counter_validate(u32 sw_if_index)
{
	gtpu_detunnel_main_t *gdm = &gtpu_detunnel_main;

	clib_warning("interface max index %u", sw_if_index);

	if (PREDICT_FALSE(gdm->counter_if_index < sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&gdm->counters[GTPU_##id], sw_if_index);
	foreach_detunnel_counter
#undef _

		for (u32 i = gdm->counter_if_index + 1; i <= sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&gdm->counters[GTPU_##id], i);
	foreach_detunnel_counter
#undef _
		}

		gdm->counter_if_index = sw_if_index;
	}
}

#endif

CLIB_MARCH_FN (gtpu_detunnel_init, clib_error_t *, vlib_main_t __clib_unused *vm)
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));

	SIMD_VEC(ipv4_version) = SIMD_SPLAT(IPV4_VERSION);
	SIMD_VEC(ipv6_version) = SIMD_SPLAT(IPV6_VERSION);

	SIMD_VEC(detunnel_output_next) = SIMD_SPLAT(GTPU_NEXT_DETUNNEL_OUTPUT);
	SIMD_VEC(ipv4_next) = SIMD_SPLAT(GTPU_NEXT_IPV4_DETUNNEL);
	SIMD_VEC(ipv6_next) = SIMD_SPLAT(GTPU_NEXT_IPV6_DETUNNEL);
	SIMD_VEC(failed_next) = SIMD_SPLAT(GTPU_NEXT_FAILED_DETUNNEL);

	return 0;
}

static clib_error_t *
gtpu_detunnel_worker_init(vlib_main_t __clib_unused *vm)
{
	gtpu_detunnel_worker_t *gdw = &gtpu_detunnel_worker;
	clib_memset(gdw->counters, 0, sizeof(gdw->counters));
	return 0;
}

static clib_error_t *
gtpu_detunnel_init(vlib_main_t *vm)
{
	gtpu_detunnel_main_t *gdm = &gtpu_detunnel_main;
	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	gdm->counter_if_index = pool_elts(im->sw_interfaces);

#define _(E, n)																\
	vlib_combined_counter_main_t *cm_##n = &gdm->counters[GTPU_##E];		\
	cm_##n->name = "gtpu_" #n;												\
	cm_##n->stat_segment_name = "/detunnel/gtpu/" #n;						\
	vlib_validate_combined_counter(cm_##n, gdm->counter_if_index);			\
	vlib_zero_combined_counter(cm_##n, gdm->counter_if_index);

	foreach_detunnel_counter
#undef _

	return CLIB_MARCH_FN_SELECT(gtpu_detunnel_init) (vm);
}

VLIB_WORKER_INIT_FUNCTION (gtpu_detunnel_worker_init);
VLIB_INIT_FUNCTION (gtpu_detunnel_init);