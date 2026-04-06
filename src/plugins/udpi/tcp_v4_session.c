#include <math.h>
#include <stdbool.h>

#include <nat/lib/lib.h>

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <vlib/vlib.h>
#include <vlib/buffer.h>
#include <vlib/node.h>
#include <vlib/threads.h>

#include <vat/vat.h>
#include <vnet/buffer.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/vnet.h>

#include <vppinfra/bihash_16_8.h>
#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>
#include <vppinfra/vec.h>

#include "vec.h"
#include "config.h"
#include "detunnel/detunnel.h"
#include "session.h"
#include "metadata_generator_funcs.h"
#include "producer.h"

#define foreach_tcp_v4_session_next							\
	_(drop_next, DROP, "drop")
enum
{
#define _(var, id, name) tcp_v4_session_NEXT_##id,
	foreach_tcp_v4_session_next
#undef _
	tcp_v4_session_NEXT_N,
};

#define _(var, id, name) static simd_u16_t simd_u16(var);

foreach_tcp_v4_session_next
#undef _

typedef struct
{
	flow_key_v4_t key;
} tcp_v4_session_trace_t;

typedef struct
{
	vlib_simple_counter_main_t create_session;
	vlib_simple_counter_main_t remove_session;
} tcp_v4_session_main_t;

typedef struct
{
	CLIB_CACHE_LINE_ALIGN_MARK (cacheline);
	f64 now;
	session_t *session_pool;
	session_v4_map session_map;
	tw_timer_wheel_1t_3w_1024sl_ov_t time_wheel;
} tcp_v4_session_worker_t;

extern __thread tcp_v4_session_worker_t *tcp_v4_session_worker;
extern tcp_v4_session_main_t tcp_v4_session_main;
extern vlib_node_registration_t tcp_v4_session;

static_always_inline void
tcp_v4_session_to_next(u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += simd_u16_size)
	{
		// simd_u16_t next_vec = simd_u16_load(next + i);

		simd_u16_t result = simd_u16(drop_next);

		simd_u16_store(result, next + i);
	}
}

// static_always_inline void
// add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
// 		const flow_key_v4_t *key)
// {
// 	if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
// 	{
// 		tcp_v4_session_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
// 		t->key = *key;
// 	}
// }

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next, u8 is_trace)
{
	next[0] = tcp_v4_session_NEXT_DROP;
	return;
}

static_always_inline u64
tcp_v4_session_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_trace)
{
	vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
	u16 nexts[VLIB_FRAME_SIZE];
	u16 *next = nexts;

	vlib_buffer_t **b = bufs;

	tcp_v4_session_worker_t *sw = tcp_v4_session_worker;

	u32 *from = vlib_frame_vector_args(frame);
	u32 n_left_from = frame->n_vectors;
	sw->now = vlib_time_now(vm);

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

	tcp_v4_session_to_next(nexts, frame->n_vectors);
	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

VLIB_NODE_FN (tcp_v4_session) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	return tcp_v4_session_inline(vm, node, frame, node->flags & VLIB_NODE_FLAG_TRACE);
}

#ifndef CLIB_MARCH_VARIANT
__thread tcp_v4_session_worker_t *tcp_v4_session_worker;
tcp_v4_session_main_t tcp_v4_session_main;

static u8 *format_tcp_v4_session_trace(u8 *s, va_list *args)
{
	vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
	vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
	tcp_v4_session_trace_t *t = va_arg(*args, tcp_v4_session_trace_t *);
	return format(s,"src ip   %U\n"
			"  dst ip   %U\n"
			"  src port %U\n"
			"  dst port %U",
			format_ip6_address, &t->key.ip[FLOW_DIRECTION_ORIGINAL],
			format_ip6_address, &t->key.ip[FLOW_DIRECTION_REVERSE],
			format_network_port, t->key.l4_protocol, t->key.port[FLOW_DIRECTION_ORIGINAL],
			format_network_port, t->key.l4_protocol, t->key.port[FLOW_DIRECTION_REVERSE]);
}

VLIB_REGISTER_NODE (tcp_v4_session) = {
	.name = "tcp-session",
	.vector_size = sizeof(u32),
	.format_trace = format_tcp_v4_session_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = tcp_v4_session_NEXT_N,
	.next_nodes = {
#define _(var, id, name) [tcp_v4_session_NEXT_##id] = (name),
	foreach_tcp_v4_session_next
#undef _
	},
};

void tcp_v4_session_counter_validate(u32 sw_idx)
{
	tcp_v4_session_main_t *sm = &tcp_v4_session_main;

	sm->create_session.name = "create_session_v4";
	sm->create_session.stat_segment_name = "/udpi/create_session_v4";
	vlib_validate_simple_counter(&sm->create_session, sw_idx);
	vlib_zero_simple_counter(&sm->create_session, sw_idx);

	sm->remove_session.name = "remove_session_v4";
	sm->remove_session.stat_segment_name = "/udpi/remove_session_v4";
	vlib_validate_simple_counter(&sm->remove_session, sw_idx);
	vlib_zero_simple_counter(&sm->remove_session, sw_idx);
}

#endif

CLIB_MARCH_FN (tcp_v4_session_init, clib_error_t *, vlib_main_t __clib_unused *vm)
{
	clib_warning("size: %lu %s", simd_u16_size, CLIB_STRING_MACRO(simd_u16_t));

	simd_u16(drop_next) = simd_u16_splat(tcp_v4_session_NEXT_DROP);

	return 0;
}

// static clib_error_t *
// tcp_v4_session_worker_init(vlib_main_t __clib_unused *vm)
// {
// 	tcp_v4_session_worker = clib_mem_alloc(sizeof(tcp_v4_session_worker_t));
// 	clib_memset(tcp_v4_session_worker, 0, sizeof(tcp_v4_session_worker_t));
// 	const udpi_session_collection_config_t *sc = &udpi_config->ipv4_config.session_collection;
// 	const udpi_time_wheel_config_t *tc = &udpi_config->ipv4_config.time_wheel;
// 	tcp_v4_session_worker_t *sw = tcp_v4_session_worker;
// 	tw_timer_wheel_1t_3w_1024sl_ov_t *tw = &sw->time_wheel;

// 	vt_init(&sw->session_map);
// 	vt_reserve(&sw->session_map,  max_pow2((u64) sc->map_capacity * 2));

// 	vlib_worker_thread_barrier_check();

// 	pool_init_fixed(sw->session_pool, sc->pool_capacity);

// 	vlib_worker_thread_barrier_check();

// 	if (!sw->session_pool)
// 		return clib_error_return(0, "failed to create session pool");

// 	tw_timer_wheel_init_1t_3w_1024sl_ov(tw, NULL, tc->resolution, tc->max_expiration);
// 	vec_validate_aligned(tw->expired_timer_handles, tc->max_expiration, CLIB_CACHE_LINE_BYTES);
// 	vec_set_len(tw->expired_timer_handles, 0);

// 	ASSERT(_vec_len(tw->expired_timer_handles) == 0);

// 	return 0;
// }

// static clib_error_t *
// tcp_v4_session_init(vlib_main_t *vm)
// {
// 	const vlib_thread_main_t *tm = vlib_get_thread_main();
// 	const u64 *p = hash_get_mem(tm->thread_registrations_by_name, "workers");
// 	const vlib_thread_registration_t *tr = (vlib_thread_registration_t *) p[0];

// 	if (tr->count == 0)
// 		tcp_v4_session_worker_init(vm);

// 	tcp_v4_session_main_t *sm = &tcp_v4_session_main;

// 	sm->create_session.name = "create_session_v4";
// 	sm->create_session.stat_segment_name = "/udpi/create_session_v4";
// 	vlib_validate_simple_counter(&sm->create_session, 0);
// 	vlib_zero_simple_counter(&sm->create_session, 0);

// 	sm->remove_session.name = "remove_session_v4";
// 	sm->remove_session.stat_segment_name = "/udpi/remove_session_v4";
// 	vlib_validate_simple_counter(&sm->remove_session, 0);
// 	vlib_zero_simple_counter(&sm->remove_session, 0);

// 	return CLIB_MARCH_FN_SELECT(tcp_v4_session_init) (vm);
// }

// VLIB_WORKER_INIT_FUNCTION (tcp_v4_session_worker_init);
// VLIB_INIT_FUNCTION (tcp_v4_session_init);