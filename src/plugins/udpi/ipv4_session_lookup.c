#include <stdbool.h>

#include <vlib/vlib.h>

#include <vnet/ip/ip4_packet.h>
#include <vnet/vnet.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include "detunnel/detunnel.h"

#include "ipv4_session.h"
#include "vlib/threads.h"
#include "vppinfra/format.h"
#include "vppinfra/vec.h"

#undef always_inline
#include <rte_hash.h>
#include <rte_jhash.h>

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

#define foreach_ipv4_session_lookup_next	\
	_(drop_next, DROP, "drop")				\

enum
{
#define _(var, id, name) IPV4_SESSION_LOOKUP_NEXT_##id,
	foreach_ipv4_session_lookup_next
#undef _
	IPV4_SESSION_LOOKUP_NEXT_N,
};

#define _(var, id, name) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_ipv4_session_lookup_next
#undef _

enum
{
#define _(id, name) IPV4_SESSION_LOOKUP_##id,
	foreach_detunnel_counter
#undef _
	IPV4_SESSION_LOOKUP_COUNTER_N,
};

typedef struct
{
	u16 next;
} ipv4_session_lookup_trace_t;

typedef struct
{
} ipv4_session_lookup_main_t;

typedef struct
{
	struct rte_hash *session_hash;
	ipv4_session_t *session_pool;
	u32 session_count;
	u32 max_sessions;
} ipv4_session_lookup_worker_t;

static __thread ipv4_session_lookup_worker_t ipv4_session_lookup_worker;
extern ipv4_session_lookup_main_t ipv4_session_lookup_main;
extern vlib_node_registration_t ipv4_session_lookup;

static_always_inline void
ipv4_session_lookup_to_next(u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE result = SIMD_VEC(drop_next);

		SIMD_STORE(result, next + i);
	}
}

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		const u16 next)
{
	if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
	{
		ipv4_session_lookup_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
		t->next = next;
	}
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next, u8 is_trace)
{
	if (is_trace)
		add_trace(vm, node, b, next[0]);
}

static_always_inline u64
ipv4_session_lookup_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_trace)
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

	ipv4_session_lookup_to_next(nexts, frame->n_vectors);
	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

VLIB_NODE_FN (ipv4_session_lookup) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	return ipv4_session_lookup_inline(vm, node, frame, node->flags & VLIB_NODE_FLAG_TRACE);
}

#ifndef CLIB_MARCH_VARIANT
ipv4_session_lookup_main_t ipv4_session_lookup_main;

static u8 *format_ipv4_session_lookup_trace(u8 *s, va_list *args)
{
	vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
	vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
	ipv4_session_lookup_trace_t *t = va_arg(*args, ipv4_session_lookup_trace_t *);
	return format(s,"next node   %u",
			t->next);
}

VLIB_REGISTER_NODE (ipv4_session_lookup) = {
	.name = "ipv4-session-lookup",
	.vector_size = sizeof(u32),
	.format_trace = format_ipv4_session_lookup_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = IPV4_SESSION_LOOKUP_NEXT_N,
	.next_nodes = {
#define _(var, id, name) [IPV4_SESSION_LOOKUP_NEXT_##id] = (name),
	foreach_ipv4_session_lookup_next
#undef _
	},
};

#endif

CLIB_MARCH_FN (ipv4_session_lookup_init, clib_error_t *, vlib_main_t __clib_unused *vm)
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));

	SIMD_VEC(drop_next) = SIMD_SPLAT(IPV4_SESSION_LOOKUP_NEXT_DROP);

	return 0;
}

static clib_error_t *
ipv4_session_lookup_worker_init(vlib_main_t __clib_unused *vm)
{
	ipv4_session_lookup_worker_t *sw = &ipv4_session_lookup_worker;
	struct rte_hash_parameters hash_params = {0};

	void *name = format(NULL, "ipv4_session_hash_%u", vlib_get_thread_index());

	hash_params.name = name;
	hash_params.entries = 1024 * 1024;  // 1M sessions
	hash_params.key_len = sizeof(ipv4_5tuple_key_t);
	hash_params.hash_func = rte_jhash;
	hash_params.hash_func_init_val = 0;
	hash_params.socket_id = (i32) rte_socket_id();
	hash_params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY;  // Multi-thread safe

	sw->session_hash = rte_hash_create(&hash_params);

	if (sw->session_hash == NULL)
	{
		vec_free(name);
		return clib_error_return(0, "Failed to create rte_hash for IPv4 sessions");
	}

	sw->max_sessions = 1024 * 1024;
	sw->session_count = 0;
	sw->session_pool = NULL;

	vec_free(name);
	return 0;
}

static clib_error_t *
ipv4_session_lookup_init(vlib_main_t *vm)
{
	return CLIB_MARCH_FN_SELECT(ipv4_session_lookup_init) (vm);
}

VLIB_WORKER_INIT_FUNCTION (ipv4_session_lookup_worker_init);
VLIB_INIT_FUNCTION (ipv4_session_lookup_init);