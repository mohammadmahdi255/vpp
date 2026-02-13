#include <asm-generic/errno.h>
#include <stdbool.h>

#include <vlib/vlib.h>

#include <vnet/ip/ip4_packet.h>
#include <vnet/vnet.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include <vppinfra/bihash_16_8.h>

#include "detunnel/detunnel.h"

#include "ipv4_session.h"
#include "rte_eal.h"
#include "vat/vat.h"
#include "vlib/buffer.h"
#include "vlib/node.h"
#include "vlib/threads.h"
#include "vnet/buffer.h"
#include "vnet/udp/udp_packet.h"
#include "vppinfra/format.h"
#include "vppinfra/pool.h"
#include "vppinfra/vec.h"

#undef always_inline
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_errno.h>

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
	clib_bihash_16_8_t session_hash;
	ipv4_session_t *session_pool;
	u32 session_count;
} ipv4_session_lookup_worker_t;

extern __thread ipv4_session_lookup_worker_t ipv4_session_lookup_worker;
extern ipv4_session_lookup_main_t ipv4_session_lookup_main;
extern vlib_node_registration_t ipv4_session_lookup;

// static_always_inline void
// ipv4_session_lookup_to_next(vlib_buffer_t **b, const void **key_ptr, i32 *position, u16 *next, u16 len)
// {
// 	// ipv4_session_lookup_worker_t *sw = &ipv4_session_lookup_worker;
// 	// for (u16 i = 0; i < len; i++)
// 	// {
// 	// 	if (position[i] < 0)
// 	// 	{
// 	// 		vnet_buffer(b[i])->udp.session_index = position[i];
// 	// 		next[i] = IPV4_SESSION_LOOKUP_NEXT_DROP;
// 	// 	}
// 	// 	else
// 	// 	{
// 	// 		u32 session_index = 1000;
// 	// 		rte_hash_add_key_data(sw->session_hash, key_ptr[i], &session_index);
// 	// 		vnet_buffer(b[i])->udp.session_index = session_index;
// 	// 		next[i] = IPV4_SESSION_LOOKUP_NEXT_DROP;
// 	// 	}
// 	// }
// }

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
	key->protocol = ip4->protocol;
	next[0] = 0;

	ipv4_session_lookup_worker_t *sw = &ipv4_session_lookup_worker;

	if (clib_bihash_search_16_8(&sw->session_hash, &kv, &kv) == 0)
	{
		vnet_buffer(b)->udp.session_index = (i32) kv.value;
		// clib_warning("found");
	}
	else
	{
		clib_warning("insert");
		pool_get(sw->session_pool, kv.value);
		clib_bihash_add_del_16_8(&sw->session_hash, &kv, 1);
		vnet_buffer(b)->udp.session_index = kv.value;
	}

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

	// ipv4_session_lookup_worker_t *sw = &ipv4_session_lookup_worker;

	// u32 offset = 0;
	// while (offset < frame->n_vectors)
	// {
	// 	u32 batch_size = clib_min(frame->n_vectors - offset, RTE_HASH_LOOKUP_BULK_MAX);
	// 	rte_hash_lookup_bulk(sw->session_hash, &key_ptrs[offset], batch_size, &positions[offset]);
	// 	offset += batch_size;
	// }

	// ipv4_session_lookup_to_next(bufs, key_ptrs, positions, nexts, frame->n_vectors);
	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

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
			format_network_port, t->key.protocol, t->key.src_port,
			format_network_port, t->key.protocol, t->key.dst_port);
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

CLIB_MARCH_FN (ipv4_session_lookup_init, clib_error_t *, vlib_main_t __clib_unused *vm)
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));

	// SIMD_VEC(drop_next) = SIMD_SPLAT(IPV4_SESSION_LOOKUP_NEXT_DROP);

	return 0;
}

static clib_error_t *
ipv4_session_lookup_worker_init(vlib_main_t __clib_unused *vm)
{
	ipv4_session_lookup_worker_t *sw = &ipv4_session_lookup_worker;

	sw->session_count = 0;
	sw->session_pool = NULL;

	void *name = format(NULL, "ipv4-session-hash-%u", vlib_get_thread_index());
	clib_bihash_init_16_8(&sw->session_hash, name, 1024, 1 << 20);
	vec_free(name);

	pool_init_fixed(sw->session_pool, 1024);

	if (!sw->session_pool)
		return clib_error_return(0, "failed to create session pool");

	return 0;
}

static clib_error_t *
ipv4_session_lookup_init(vlib_main_t *vm)
{
	return CLIB_MARCH_FN_SELECT(ipv4_session_lookup_init) (vm);
}

VLIB_WORKER_INIT_FUNCTION (ipv4_session_lookup_worker_init) = {
	.runs_after = VLIB_INITS("dpdk_worker_thread_init"),
};

VLIB_INIT_FUNCTION (ipv4_session_lookup_init);

#endif