#include <math.h>
#include <stdbool.h>

#include <vat/vat.h>

#include <vlib/vlib.h>
#include <vlib/buffer.h>
#include <vlib/node.h>
#include <vlib/threads.h>

#include <vnet/buffer.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>
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

#include "ipv4_session.h"

#define foreach_ipv4_session_lookup_next	\
	_(drop_next, DROP, "drop")				\
	_(tcp_next, TCP_SESSION, "ip4-drop")	\
	_(udp_next, UDP_SESSION, "ip6-drop")	\

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

#define SESSION_TIMEOUT	3

enum
{
#define _(id, name) IPV4_SESSION_LOOKUP_##id,
	foreach_detunnel_counter
#undef _
	IPV4_SESSION_LOOKUP_COUNTER_N,
};

typedef struct
{
	ipv4_flow_key_t key;
} ipv4_session_lookup_trace_t;

typedef struct
{
} ipv4_session_lookup_main_t;

typedef struct
{
	f64 now;
	ipv4_session_t *session_pool;
	clib_bihash_16_8_t session_hash;
	tw_timer_wheel_1t_3w_1024sl_ov_t time_wheel;
} ipv4_session_lookup_worker_t;

extern __thread ipv4_session_lookup_worker_t ipv4_session_lookup_worker;
extern ipv4_session_lookup_main_t ipv4_session_lookup_main;
extern vlib_node_registration_t ipv4_session_lookup;

static_always_inline void
ipv4_session_lookup_to_next(u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE next_vec = SIMD_LOAD(next + i);
		SIMD_TYPE tcp_mask_vec = (next_vec == SIMD_VEC(tcp_protocol));
		SIMD_TYPE udp_mask_vec = (next_vec == SIMD_VEC(udp_protocol));

		SIMD_TYPE result = SIMD_VEC(drop_next) |
				(tcp_mask_vec & SIMD_VEC(tcp_next)) |
				(udp_mask_vec & SIMD_VEC(udp_next));

		SIMD_STORE(result, next + i);
	}
}

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		const ipv4_flow_key_t *key)
{
	if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
	{
		ipv4_session_lookup_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
		t->key = *key;
	}
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next, u8 is_trace)
{
	const ip4_header_t *ip4 = (void *) b->data + vnet_buffer(b)->l3_hdr_offset;
	const udp_header_t *udp = (void *) b->data + vnet_buffer(b)->l4_hdr_offset;

	clib_bihash_kv_16_8_t kv;

	ipv4_flow_key_t *key = (void *) &kv.key;

	key->src_ip = ip4->src_address;
	key->dst_ip = ip4->dst_address;
	key->src_port = udp->src_port;
	key->dst_port = udp->dst_port;
	key->l4_protocol = ip4->protocol;
	next[0] = ip4->protocol;

	ipv4_session_lookup_worker_t *sw = &ipv4_session_lookup_worker;
	session_flow_t *session_flow = vnet_buffer_get_opaque(b);
	ipv4_session_t *session;

	if (clib_bihash_search_16_8(&sw->session_hash, &kv, &kv))
	{
		pool_get_aligned(sw->session_pool, session, CLIB_CACHE_LINE_BYTES);
		session_flow->direction = FLOW_DIRECTION_CLIENT_TO_SERVER;
		session_flow->index = session - sw->session_pool;

		session->key = *key;
		session->start_time = sw->now;
		kv.value = session_flow->as_u64;

		clib_bihash_add_del_16_8(&sw->session_hash, &kv, 1);

		// clib_warning("Timer added! %u %lu\n", session_flow->index, kv.value);
		tw_timer_start_1t_3w_1024sl_ov(&sw->time_wheel, kv.value, 0, SESSION_TIMEOUT);

		key->src_ip = ip4->dst_address;
		key->dst_ip = ip4->src_address;
		key->src_port = udp->dst_port;
		key->dst_port = udp->src_port;

		session_flow_t *reverse_session_flow = (void *)&kv.value;
		reverse_session_flow->direction = FLOW_DIRECTION_SERVER_TO_CLIENT;

		clib_bihash_add_del_16_8(&sw->session_hash, &kv, 1);
	}
	else
	{
		session_flow->as_u64 = kv.value;
		session = pool_elt_at_index(sw->session_pool, session_flow->index);
	}

	session->end_time = sw->now + SESSION_TIMEOUT;

	session->counter[session_flow->direction].packets++;
	session->counter[session_flow->direction].bytes += vlib_buffer_length_in_chain(vm, b);

	if (is_trace)
		add_trace(vm, node, b, key);
}

static_always_inline u64
ipv4_session_lookup_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_trace)
{
	vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
	u16 nexts[VLIB_FRAME_SIZE];
	u16 *next = nexts;

	vlib_buffer_t **b = bufs;

	ipv4_session_lookup_worker_t *sw = &ipv4_session_lookup_worker;

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

	ipv4_session_lookup_to_next(nexts, frame->n_vectors);
	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	tw_timer_expire_timers_1t_3w_1024sl_ov(&sw->time_wheel, sw->now);

	return frame->n_vectors;
}

VLIB_NODE_FN (ipv4_session_lookup) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	return ipv4_session_lookup_inline(vm, node, frame, node->flags & VLIB_NODE_FLAG_TRACE);
}

#ifndef CLIB_MARCH_VARIANT

__thread ipv4_session_lookup_worker_t ipv4_session_lookup_worker;
ipv4_session_lookup_main_t ipv4_session_lookup_main;

static u8 *format_ipv4_session_lookup_trace(u8 *s, va_list *args)
{
	vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
	vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
	ipv4_session_lookup_trace_t *t = va_arg(*args, ipv4_session_lookup_trace_t *);
	return format(s,"src ip   %U\n"
			"  dst ip   %U\n"
			"  src port %U\n"
			"  dst port %U",
			format_ip4_address, &t->key.src_ip,
			format_ip4_address, &t->key.dst_ip,
			format_network_port, t->key.l4_protocol, t->key.src_port,
			format_network_port, t->key.l4_protocol, t->key.dst_port);
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
	SIMD_VEC(tcp_next) = SIMD_SPLAT(IPV4_SESSION_LOOKUP_NEXT_TCP_SESSION);
	SIMD_VEC(udp_next) = SIMD_SPLAT(IPV4_SESSION_LOOKUP_NEXT_UDP_SESSION);

	return 0;
}

static void
expired_timer_callback(u32 *session_indexes)
{
	for (u32 i = 0; i < vec_len(session_indexes); i++)
	{
		u32 session_index = session_indexes[i];

		ipv4_session_lookup_worker_t *sw = &ipv4_session_lookup_worker;
		ipv4_session_t *session =  pool_elt_at_index(sw->session_pool, session_index);

		if (session->end_time > sw->now)
		{
			// clib_warning("Timer update! %u\n", session_index);
			const u64 timeout = floor(session->end_time - sw->now);
			tw_timer_start_1t_3w_1024sl_ov(&sw->time_wheel, session_index, 0, timeout);
		}
		else
		{
			// clib_warning("Timer expired! %u\n", session_index);
			clib_bihash_kv_16_8_t *kv = (void *) &session->key;
			clib_bihash_add_del_16_8(&sw->session_hash, kv, 0);
			pool_put_index(sw->session_pool, session_index);
		}
	}
}

static clib_error_t *
ipv4_session_lookup_worker_init(vlib_main_t *vm)
{
	ipv4_session_lookup_worker_t *sw = &ipv4_session_lookup_worker;

	sw->session_pool = NULL;

	const u32 max_sessions = 1024;
	const u32 nbuckets = clib_max(max_pow2(max_sessions / 4), 64);
	const u64 memory_size = max_sessions * sizeof(clib_bihash_kv_16_8_t);

	void *name = format(NULL, "ipv4-session-hash-%u", vlib_get_thread_index());
	clib_bihash_init_16_8(&sw->session_hash, name,  nbuckets, memory_size);
	vec_free(name);

	pool_init_fixed(sw->session_pool, max_sessions);

	if (!sw->session_pool)
		return clib_error_return(0, "failed to create session pool");

  	tw_timer_wheel_init_1t_3w_1024sl_ov(&sw->time_wheel, expired_timer_callback, 1.0, VLIB_FRAME_SIZE);

	return 0;
}

static clib_error_t *
ipv4_session_lookup_init(vlib_main_t *vm)
{
	return CLIB_MARCH_FN_SELECT(ipv4_session_lookup_init) (vm);
}

VLIB_WORKER_INIT_FUNCTION (ipv4_session_lookup_worker_init);
VLIB_INIT_FUNCTION (ipv4_session_lookup_init);