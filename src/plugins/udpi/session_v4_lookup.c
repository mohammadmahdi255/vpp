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
#include "ip_session.h"
#include "metadata_generator_funcs.h"
#include "producer.h"
#include "vppinfra/vec_bootstrap.h"

#define foreach_session_v4_lookup_next	\
	_(drop_next, DROP, "drop")			\

enum
{
#define _(var, id, name) SESSION_V4_LOOKUP_NEXT_##id,
	foreach_session_v4_lookup_next
#undef _
	SESSION_V4_LOOKUP_NEXT_N,
};

#define _(var, id, name) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_session_v4_lookup_next
#undef _

enum
{
#define _(id, name) SESSION_V4_LOOKUP_##id,
	foreach_detunnel_counter
#undef _
	SESSION_V4_LOOKUP_COUNTER_N,
};

typedef struct
{
	ipv4_flow_key_t key;
} session_v4_lookup_trace_t;

typedef struct
{
	vlib_simple_counter_main_t create_session;
	vlib_simple_counter_main_t find_session;
	vlib_simple_counter_main_t remove_session;
} session_v4_lookup_main_t;

typedef struct
{
	CLIB_CACHE_LINE_ALIGN_MARK (cacheline);
	f64 now;
	ipv4_session_t *session_pool;
	session_v4_map session_map;
	tw_timer_wheel_1t_3w_1024sl_ov_t time_wheel;

	rd_kafka_message_t *msgs;
} session_v4_lookup_worker_t;

extern __thread session_v4_lookup_worker_t *session_v4_lookup_worker;
extern session_v4_lookup_main_t session_v4_lookup_main;
extern vlib_node_registration_t session_v4_lookup;
extern vlib_node_registration_t session_v4_timer_expiration;
extern vlib_node_registration_t session_v4_timer_expiration_process;

static_always_inline void
session_v4_lookup_to_next(u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE __clib_unused next_vec = SIMD_LOAD(next + i);

		SIMD_TYPE result = SIMD_VEC(drop_next);

		SIMD_STORE(result, next + i);
	}
}

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		const ipv4_flow_key_t *key)
{
	if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
	{
		session_v4_lookup_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
		t->key = *key;
	}
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next, u8 is_trace)
{
	const ip4_header_t *ip4 = (void *) b->data + vnet_buffer(b)->l3_hdr_offset;
	const nat_tcp_udp_header_t *nat_tcp_udp = (void *) b->data + vnet_buffer(b)->l4_hdr_offset;
	session_v4_lookup_main_t *sm = &session_v4_lookup_main;

	ipv4_flow_key_t key;

	key.src_ip = ip4->src_address;
	key.dst_ip = ip4->dst_address;
	key.src_port = nat_tcp_udp->src_port;
	key.dst_port = nat_tcp_udp->dst_port;
	key.l4_protocol = ip4->protocol;
	next[0] = SESSION_V4_LOOKUP_NEXT_DROP;

	session_v4_lookup_worker_t *sw = session_v4_lookup_worker;
	session_flow_t *sf = vnet_buffer_get_opaque(b);
	ipv4_session_t *session;

	session_v4_map_itr it = vt_get(&sw->session_map, key);

	if (vt_is_end(it))
	{
		pool_get_aligned(sw->session_pool, session, CLIB_CACHE_LINE_BYTES);

		sf->index = session - sw->session_pool;
		sf->direction = FLOW_DIRECTION_CLIENT_TO_SERVER;

		it = session_v4_map_insert_raw(&sw->session_map, key, sf, true, true);

		if (PREDICT_FALSE(vt_is_end(it)))
		{
			pool_put(sw->session_pool, session);
			next[0] = SESSION_V4_LOOKUP_NEXT_DROP;
			goto trace;
		}

		// adding reverse flow
		ipv4_flow_key_t rkey;
		session_flow_t rsf;

		rkey.src_ip = ip4->dst_address;
		rkey.dst_ip = ip4->src_address;
		rkey.src_port = nat_tcp_udp->dst_port;
		rkey.dst_port = nat_tcp_udp->src_port;
		rkey.l4_protocol = ip4->protocol;
		rsf.index = sf->index;
		rsf.direction = FLOW_DIRECTION_SERVER_TO_CLIENT;

		session_v4_map_itr rit = session_v4_map_insert_raw(&sw->session_map, rkey, &rsf, true, true);

		if (PREDICT_FALSE(vt_is_end(rit)))
		{
			vt_erase_itr(&sw->session_map, it);
			pool_put(sw->session_pool, session);
			next[0] = SESSION_V4_LOOKUP_NEXT_DROP;
			goto trace;
		}

		session->key = key;
		session->start_time = sw->now;
		session->counter[FLOW_DIRECTION_SERVER_TO_CLIENT] = (vlib_counter_t) {0};
		session->counter[FLOW_DIRECTION_CLIENT_TO_SERVER] = (vlib_counter_t) {0};

		tw_timer_start_1t_3w_1024sl_ov(&sw->time_wheel, sf->index, 0, SESSION_TIMEOUT);

		vlib_increment_simple_counter(&sm->create_session, vm->thread_index, 0, 1);
	}
	else
	{
		*sf = it.data->val;
		session = pool_elt_at_index(sw->session_pool, sf->index);
		vlib_increment_simple_counter(&sm->find_session, vm->thread_index, 0, 1);
	}

	session->end_time = sw->now + SESSION_TIMEOUT;

	session->counter[sf->direction].packets++;
	session->counter[sf->direction].bytes += vlib_buffer_length_in_chain(vm, b);

trace:
	if (is_trace)
		add_trace(vm, node, b, &key);
}

static_always_inline u64
session_v4_lookup_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_trace)
{
	vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
	u16 nexts[VLIB_FRAME_SIZE];
	u16 *next = nexts;

	vlib_buffer_t **b = bufs;

	session_v4_lookup_worker_t *sw = session_v4_lookup_worker;

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

	session_v4_lookup_to_next(nexts, frame->n_vectors);
	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

VLIB_NODE_FN (session_v4_lookup) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	return session_v4_lookup_inline(vm, node, frame, node->flags & VLIB_NODE_FLAG_TRACE);
}

VLIB_NODE_FN (session_v4_timer_expiration) (vlib_main_t *vm, vlib_node_runtime_t __clib_unused *node,
		vlib_frame_t __clib_unused *frame)
{
	const producer_worker_t *pw = producer_worker;
	const udpi_time_wheel_config_t *tc = &udpi_config->ipv4_config.time_wheel;
	session_v4_lookup_main_t *sm = &session_v4_lookup_main;
	session_v4_lookup_worker_t *sw = session_v4_lookup_worker;
	tw_timer_wheel_1t_3w_1024sl_ov_t *tw = &sw->time_wheel;
	ipv4_session_t *session;
	u32 n_remove = 0;
	i32 rv;
	rd_kafka_message_t msg = {
		.partition = RD_KAFKA_PARTITION_UA,
		.key = NULL,
		.key_len = 0,
		._private = pw->buffer_ring,
	};

	sw->now = vlib_time_now(vm);
	tw->expired_timer_handles = tw_timer_expire_timers_vec_1t_3w_1024sl_ov(tw, sw->now, tw->expired_timer_handles);
	u32 *session_indices = tw->expired_timer_handles;

	const u32 n_expire = clib_min(_vec_len(session_indices), tc->max_expiration);

	for (u32 i = 0; i < n_expire; i++)
	{
		u32 session_index = vec_elt(session_indices, i);
		session = pool_elt_at_index(sw->session_pool, session_index);

		if (session->end_time - sw->now > tc->resolution)
		{
			const u64 timeout = floor(session->end_time - sw->now);
			tw_timer_start_1t_3w_1024sl_ov(&sw->time_wheel, session_index, 0, timeout);
			continue;
		}

		ipv4_flow_key_t rkey;
		rkey.src_ip = session->dst_ip;
		rkey.dst_ip = session->src_ip;
		rkey.src_port = session->dst_port;
		rkey.dst_port = session->src_port;
		rkey.l4_protocol = session->l4_protocol;

		vt_erase(&sw->session_map, session->key);
		vt_erase(&sw->session_map, rkey);

		u8 *buffer = NULL;

		rv = rte_ring_sc_dequeue(pw->buffer_ring, (void **) &buffer);
		if (rv)
			vec_validate(buffer, 1 << 8);

		buffer = produce_v4_csv_record(buffer, session);
		pool_put_index(sw->session_pool, session_index);

		msg.payload = buffer;
		msg.len = _vec_len(buffer);

		vec_add1(sw->msgs, msg);

		n_remove++;
	}

	u32 n_send = rd_kafka_produce_batch(pt->rkt, RD_KAFKA_PARTITION_UA, 0, sw->msgs, _vec_len(sw->msgs));
	rd_kafka_poll(pt->rk, 0);

	vec_fast_delete(sw->msgs, n_send, 0);
	vec_fast_delete(session_indices, n_expire, 0);

	vlib_increment_simple_counter(&sm->remove_session, vm->thread_index, 0, n_remove);

	return n_remove;
}

VLIB_NODE_FN (session_v4_timer_expiration_process) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	const vlib_thread_main_t *tm = vlib_get_thread_main();
	const u64 *p = hash_get_mem(tm->thread_registrations_by_name, "workers");
	const vlib_thread_registration_t *tr = (const vlib_thread_registration_t *) p[0];
	const udpi_time_wheel_config_t *tc = &udpi_config->ipv4_config.time_wheel;

	if (tr->count == 0)
	{
		while (true)
		{
			(void) vlib_process_wait_for_event_or_clock(vm, tc->interval);
			session_v4_timer_expiration.function(vm, node, frame);
		}
	}

	while (true)
	{
		(void) vlib_process_wait_for_event_or_clock(vm, tc->interval);

		for (u32 i = 0; i < tr->count; i++)
			vlib_node_set_interrupt_pending(vlib_get_main_by_index(tr->first_index + i), session_v4_timer_expiration.index);
	}

	return 0;
}

#ifndef CLIB_MARCH_VARIANT
__thread session_v4_lookup_worker_t *session_v4_lookup_worker;
session_v4_lookup_main_t session_v4_lookup_main;

static u8 *format_session_v4_lookup_trace(u8 *s, va_list *args)
{
	vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
	vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
	session_v4_lookup_trace_t *t = va_arg(*args, session_v4_lookup_trace_t *);
	return format(s,"src ip   %U\n"
			"  dst ip   %U\n"
			"  src port %U\n"
			"  dst port %U",
			format_ip4_address, &t->key.src_ip,
			format_ip4_address, &t->key.dst_ip,
			format_network_port, t->key.l4_protocol, t->key.src_port,
			format_network_port, t->key.l4_protocol, t->key.dst_port);
}

VLIB_REGISTER_NODE (session_v4_lookup) = {
	.name = "session-v4-lookup",
	.vector_size = sizeof(u32),
	.format_trace = format_session_v4_lookup_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = SESSION_V4_LOOKUP_NEXT_N,
	.next_nodes = {
#define _(var, id, name) [SESSION_V4_LOOKUP_NEXT_##id] = (name),
	foreach_session_v4_lookup_next
#undef _
	},
};

VLIB_REGISTER_NODE (session_v4_timer_expiration) = {
	.name = "session-v4-timer-expiration",
	.type = VLIB_NODE_TYPE_SCHED,
	.state = VLIB_NODE_STATE_INTERRUPT
};

VLIB_REGISTER_NODE (session_v4_timer_expiration_process) = {
	.name = "session-v4-timer-expiration-process",
	.type = VLIB_NODE_TYPE_PROCESS,
};

#endif

CLIB_MARCH_FN (session_v4_lookup_init, clib_error_t *, vlib_main_t __clib_unused *vm)
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));

	SIMD_VEC(drop_next) = SIMD_SPLAT(SESSION_V4_LOOKUP_NEXT_DROP);

	return 0;
}

static clib_error_t *
session_v4_lookup_worker_init(vlib_main_t __clib_unused *vm)
{
	session_v4_lookup_worker = clib_mem_alloc(sizeof(session_v4_lookup_worker_t));
	clib_memset(session_v4_lookup_worker, 0, sizeof(session_v4_lookup_worker_t));
	const udpi_session_collection_config_t *sc = &udpi_config->ipv4_config.session_collection;
	const udpi_time_wheel_config_t *tc = &udpi_config->ipv4_config.time_wheel;
	session_v4_lookup_worker_t *sw = session_v4_lookup_worker;
	tw_timer_wheel_1t_3w_1024sl_ov_t *tw = &sw->time_wheel;

	vt_init(&sw->session_map);
	vt_reserve(&sw->session_map,  max_pow2((u64) sc->map_capacity * 2));

	vlib_worker_thread_barrier_check();

	pool_init_fixed(sw->session_pool, sc->pool_capacity);

	vlib_worker_thread_barrier_check();

	vec_validate_aligned(sw->msgs, tc->max_expiration, CLIB_CACHE_LINE_BYTES);
	vec_set_len(sw->msgs, 0);

	if (!sw->session_pool)
		return clib_error_return(0, "failed to create session pool");

	tw_timer_wheel_init_1t_3w_1024sl_ov(tw, NULL, tc->resolution, tc->max_expiration);
	vec_validate_aligned(tw->expired_timer_handles, tc->max_expiration, CLIB_CACHE_LINE_BYTES);
	vec_set_len(tw->expired_timer_handles, 0);

	ASSERT(_vec_len(sw->msgs) == 0);
	ASSERT(_vec_len(tw->expired_timer_handles) == 0);

	return 0;
}

static clib_error_t *
session_v4_lookup_init(vlib_main_t *vm)
{
	const vlib_thread_main_t *tm = vlib_get_thread_main();
	const u64 *p = hash_get_mem(tm->thread_registrations_by_name, "workers");
	const vlib_thread_registration_t *tr = (vlib_thread_registration_t *) p[0];

	if (tr->count == 0)
		session_v4_lookup_worker_init(vm);

	session_v4_lookup_main_t *sm = &session_v4_lookup_main;

	sm->create_session.name = "create_session_v4";
	sm->create_session.stat_segment_name = "/udpi/ipv4/create_session_v4";
	vlib_validate_simple_counter(&sm->create_session, 0);
	vlib_zero_simple_counter(&sm->create_session, 0);

	sm->find_session.name = "find_session_v4";
	sm->find_session.stat_segment_name = "/udpi/ipv4/find_session_v4";
	vlib_validate_simple_counter(&sm->find_session, 0);
	vlib_zero_simple_counter(&sm->find_session, 0);

	sm->remove_session.name = "remove_session_v4";
	sm->remove_session.stat_segment_name = "/udpi/ipv4/remove_session_v4";
	vlib_validate_simple_counter(&sm->remove_session, 0);
	vlib_zero_simple_counter(&sm->remove_session, 0);

	return CLIB_MARCH_FN_SELECT(session_v4_lookup_init) (vm);
}

VLIB_WORKER_INIT_FUNCTION (session_v4_lookup_worker_init);
VLIB_INIT_FUNCTION (session_v4_lookup_init);