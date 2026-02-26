#include <math.h>
#include <stdbool.h>

#include <nat/lib/lib.h>

#include <stdint.h>
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

#include "detunnel/detunnel.h"
#include "config.h"
#include "ip_session.h"
#include "producer.h"
#include "boost_flat_map_16_8.h"
#include "boost_flat_map_40_8.h"

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
} session_v4_lookup_main_t;

typedef struct
{
	CLIB_CACHE_LINE_ALIGN_MARK (cacheline);
	f64 now;
	ipv4_session_t *session_pool;
	clib_bihash_16_8_t session_hash;
	boost_flat_map_16_8_t* session_hash2;
	tw_timer_wheel_1t_3w_1024sl_ov_t time_wheel;
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
	const producer_worker_t *pw = producer_worker;
	const ip4_header_t *ip4 = (void *) b->data + vnet_buffer(b)->l3_hdr_offset;
	const nat_tcp_udp_header_t *nat_tcp_udp = (void *) b->data + vnet_buffer(b)->l4_hdr_offset;
	i32 failed;

	clib_bihash_kv_16_8_t kv;

	ipv4_flow_key_t *key = (void *) &kv.key;

	key->src_ip = ip4->src_address;
	key->dst_ip = ip4->dst_address;
	key->src_port = nat_tcp_udp->src_port;
	key->dst_port = nat_tcp_udp->dst_port;
	key->l4_protocol = ip4->protocol;
	next[0] = SESSION_V4_LOOKUP_NEXT_DROP;

	session_v4_lookup_worker_t *sw = session_v4_lookup_worker;
	session_flow_t *sf = vnet_buffer_get_opaque(b);
	ipv4_session_t *session;

	if (clib_bihash_search_16_8(&sw->session_hash, &kv, &kv))
	{
		const i32 rv = rte_ring_sc_dequeue(pw->release_session_v4_ring, (void **) &session);
		if (rv)
			pool_get_aligned(sw->session_pool, session, CLIB_CACHE_LINE_BYTES);

		sf->index = session - sw->session_pool;
		sf->direction = FLOW_DIRECTION_CLIENT_TO_SERVER;

		session->key = *key;
		session->start_time = sw->now;
		session->counter[FLOW_DIRECTION_SERVER_TO_CLIENT] = (vlib_counter_t) {0};
		session->counter[FLOW_DIRECTION_CLIENT_TO_SERVER] = (vlib_counter_t) {0};
		kv.value = sf->as_u64;

		failed = clib_bihash_add_del_16_8(&sw->session_hash, &kv, 1);
		if (PREDICT_FALSE(failed))
		{
			pool_put(sw->session_pool, session);
			next[0] = SESSION_V4_LOOKUP_NEXT_DROP;
			return;
		}

		// adding reverse flow
		clib_bihash_kv_16_8_t rkv;
		ipv4_flow_key_t *rkey = (void *) &rkv.key;
		session_flow_t *rsf = (void *)&rkv.value;

		rkey->src_ip = ip4->dst_address;
		rkey->dst_ip = ip4->src_address;
		rkey->src_port = nat_tcp_udp->dst_port;
		rkey->dst_port = nat_tcp_udp->src_port;
		rkey->l4_protocol = ip4->protocol;
		rsf->index = sf->index;
		rsf->direction = FLOW_DIRECTION_SERVER_TO_CLIENT;

		failed = clib_bihash_add_del_16_8(&sw->session_hash, &kv, 1);
		if (PREDICT_FALSE(failed))
		{
			clib_bihash_add_del_16_8(&sw->session_hash, &kv, 0);
			pool_put(sw->session_pool, session);
			next[0] = SESSION_V4_LOOKUP_NEXT_DROP;
			return;
		}

		// clib_warning("Timer added! rv %d %u %u\n" , rv, sf->index, sf->direction);
		tw_timer_start_1t_3w_1024sl_ov(&sw->time_wheel, sf->index, 0, SESSION_TIMEOUT);
	}
	else
	{
		sf->as_u64 = kv.value;
		session = pool_elt_at_index(sw->session_pool, sf->index);
	}

	session->end_time = sw->now + SESSION_TIMEOUT;

	session->counter[sf->direction].packets++;
	session->counter[sf->direction].bytes += vlib_buffer_length_in_chain(vm, b);

	if (is_trace)
		add_trace(vm, node, b, key);
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
	// const producer_worker_t *pw = producer_worker;
	const udpi_time_wheel_config_t *tc = &udpi_config->time_wheel;
	session_v4_lookup_worker_t *sw = session_v4_lookup_worker;
	tw_timer_wheel_1t_3w_1024sl_ov_t *tw = &sw->time_wheel;
	ipv4_session_t *session;

	sw->now = vlib_time_now(vm);
	tw->expired_timer_handles = tw_timer_expire_timers_vec_1t_3w_1024sl_ov(tw, sw->now, tw->expired_timer_handles);
	u32 *session_indices = tw->expired_timer_handles;

	const u32 max_size = clib_min(_vec_len(session_indices), tc->max_expiration);

	for (u32 i = 1; i <= max_size; i++)
	{
		// const i32 rv = rte_ring_sc_dequeue(pw->release_session_v4_ring, (void **) &session);
		// if (!rv)
		// 	pool_put(sw->session_pool, session);

		u32 session_index = vec_elt(session_indices, _vec_len(session_indices) - i);
		session = pool_elt_at_index(sw->session_pool, session_index);

		if (session->end_time - sw->now > tc->resolution)
		{
			const u64 timeout = floor(session->end_time - sw->now);
			tw_timer_start_1t_3w_1024sl_ov(&sw->time_wheel, session_index, 0, timeout);
		}
		else
		{
			clib_bihash_kv_16_8_t *kv = (void *) &session->key;
			clib_bihash_add_del_16_8(&sw->session_hash, kv, 0);

			clib_bihash_kv_16_8_t reverse_kv;
			ipv4_flow_key_t *key = (ipv4_flow_key_t *) &reverse_kv.key;

			key->src_ip = session->dst_ip;
			key->dst_ip = session->src_ip;
			key->src_port = session->dst_port;
			key->dst_port = session->src_port;
			key->l4_protocol = session->l4_protocol;

			clib_bihash_add_del_16_8(&sw->session_hash, &reverse_kv, 0);

			// const i32 rv = rte_ring_sp_enqueue(pw->acquire_session_v4_ring, (void *) session);
			// if (rv)
			// {
				pool_put_index(sw->session_pool, session_index);
			// 	clib_warning("failed to enqueeu session");
			// }
		}
	}

	vec_dec_len(session_indices, max_size);
	return max_size;
}

VLIB_NODE_FN (session_v4_timer_expiration_process) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	const vlib_thread_main_t *tm = vlib_get_thread_main();
	const u64 *p = hash_get_mem(tm->thread_registrations_by_name, "workers");
	const vlib_thread_registration_t *tr = (const vlib_thread_registration_t *) p[0];
	const udpi_time_wheel_config_t *tc = &udpi_config->time_wheel;

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
	const udpi_session_collection_config_t *sc = &udpi_config->session_collection;
	const udpi_time_wheel_config_t *tc = &udpi_config->time_wheel;
	session_v4_lookup_worker_t *sw = session_v4_lookup_worker;
	tw_timer_wheel_1t_3w_1024sl_ov_t *tw = &sw->time_wheel;

	const u32 max_entries = sc->bihash_capacity * 2; /* forward + reverse */
	// const u32 nbuckets = clib_max(max_pow2 (max_entries / BIHASH_KVP_PER_PAGE), 64);
	// const u64 memory_size = (u64) nbuckets * BIHASH_KVP_PER_PAGE * sizeof(clib_bihash_kv_16_8_t);

	// void *name = format(NULL, "session-v4-table-%u", vlib_get_thread_index());
	// clib_bihash_init_16_8(&sw->session_hash, name, nbuckets, memory_size);
	// vec_free(name);

	sw->session_hash2 = boost_flat_map_16_8_init(max_entries);

	vlib_worker_thread_barrier_check();

	pool_init_fixed(sw->session_pool, sc->pool_capacity);

	vlib_worker_thread_barrier_check();

	if (!sw->session_pool)
		return clib_error_return(0, "failed to create session pool");

	tw_timer_wheel_init_1t_3w_1024sl_ov(tw, NULL, tc->resolution, tc->max_expiration);
	vec_resize_aligned(tw->expired_timer_handles, tc->max_expiration, CLIB_CACHE_LINE_BYTES);
	vec_reset_length(tw->expired_timer_handles);

	ASSERT(vec_len(tw->expired_timer_handles) == 0);

	return 0;
}

static clib_error_t *
session_v4_lookup_init(vlib_main_t *vm)
{
	const vlib_thread_main_t *tm = vlib_get_thread_main();
	const u64 *p = hash_get_mem(tm->thread_registrations_by_name, "workers");
	const vlib_thread_registration_t *tr = (vlib_thread_registration_t *) p[0];

	boost_flat_map_16_8_hello_world();
	// boost_flat_map_session_v6_hello_world();

	if (tr->count == 0)
		session_v4_lookup_worker_init(vm);

	return CLIB_MARCH_FN_SELECT(session_v4_lookup_init) (vm);
}

VLIB_WORKER_INIT_FUNCTION (session_v4_lookup_worker_init);
VLIB_INIT_FUNCTION (session_v4_lookup_init);