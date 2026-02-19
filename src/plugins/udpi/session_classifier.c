#include <stdbool.h>

#include <vlib/vlib.h>

#include <vnet/ip/ip4_packet.h>
#include <vnet/vnet.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include "detunnel/detunnel.h"

#define foreach_session_classifier_next									\
	_(drop_next, DROP, "drop")											\
	_(session_v4_next, SESSION_V4_LOOKUP, "session-v4-lookup")			\
	_(session_v6_next, SESSION_V6_LOOKUP, "session-v6-lookup")

#define foreach_session_classifier	\
	_(ipv4_version)					\
	_(ipv6_version)					\

#define IPV4_VERSION	0x0040
#define IPV6_VERSION	0x0060

enum
{
#define _(var, id, name) SESSION_CLASSIFIER_NEXT_##id,
	foreach_session_classifier_next
#undef _
	SESSION_CLASSIFIER_NEXT_N,
};

#define _(var, id, name) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_session_classifier_next
#undef _

#define _(var) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_session_classifier
#undef _

enum
{
#define _(id, name) SESSION_CLASSIFIER_##id,
	foreach_detunnel_counter
#undef _
	SESSION_CLASSIFIER_COUNTER_N,
};

typedef struct
{
	u16 next;
} session_trace_t;

extern vlib_node_registration_t session_classifier;

static_always_inline void
session_to_next(u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE next_vec = SIMD_LOAD(next + i);
		SIMD_TYPE ipv4_mask_vec = (next_vec == SIMD_VEC(ipv4_version));
		SIMD_TYPE ipv6_mask_vec = (next_vec == SIMD_VEC(ipv6_version));

		SIMD_TYPE result = SIMD_VEC(drop_next) |
				(ipv4_mask_vec & SIMD_VEC(session_v4_next)) |
				(ipv6_mask_vec & SIMD_VEC(session_v6_next));

		SIMD_STORE(result, next + i);
	}
}

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		const u16 next)
{
	if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
	{
		session_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
		t->next = next;
	}
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next, u8 is_trace)
{
	const u8 *l3_data = b->data + vnet_buffer(b)->l3_hdr_offset;
	next[0] = *l3_data & 0x00F0;

	if (is_trace)
		add_trace(vm, node, b, next[0]);
}

static_always_inline u64
session_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_trace)
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

	session_to_next(nexts, frame->n_vectors);
	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

VLIB_NODE_FN (session_classifier) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	return session_inline(vm, node, frame, node->flags & VLIB_NODE_FLAG_TRACE);
}

#ifndef CLIB_MARCH_VARIANT
static u8 *format_session_trace(u8 *s, va_list *args)
{
	vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
	vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
	session_trace_t *t = va_arg(*args, session_trace_t *);
	return format(s,"next node   0x%04x",
			t->next);
}

VLIB_REGISTER_NODE (session_classifier) = {
	.name = "session-classifier",
	.vector_size = sizeof(u32),
	.format_trace = format_session_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = SESSION_CLASSIFIER_NEXT_N,
	.next_nodes = {
#define _(var, id, name) [SESSION_CLASSIFIER_NEXT_##id] = (name),
	foreach_session_classifier_next
#undef _
	},
};

#endif

CLIB_MARCH_FN (session_init, clib_error_t *, vlib_main_t __clib_unused *vm)
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));

	SIMD_VEC(ipv4_version) = SIMD_SPLAT(IPV4_VERSION);
	SIMD_VEC(ipv6_version) = SIMD_SPLAT(IPV6_VERSION);

	SIMD_VEC(drop_next) = SIMD_SPLAT(SESSION_CLASSIFIER_NEXT_DROP);
	SIMD_VEC(session_v4_next) = SIMD_SPLAT(SESSION_CLASSIFIER_NEXT_SESSION_V4_LOOKUP);
	SIMD_VEC(session_v6_next) = SIMD_SPLAT(SESSION_CLASSIFIER_NEXT_SESSION_V6_LOOKUP);

	return 0;
}

static clib_error_t *
session_worker_init(vlib_main_t __clib_unused *vm)
{
	return 0;
}

static clib_error_t *
session_init(vlib_main_t *vm)
{
	return CLIB_MARCH_FN_SELECT(session_init) (vm);
}

VLIB_WORKER_INIT_FUNCTION (session_worker_init);
VLIB_INIT_FUNCTION (session_init);