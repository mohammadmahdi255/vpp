#ifndef UDPI_SESSION_H_
#define UDPI_SESSION_H_

#include <vlib/counter_types.h>
#include <vlib/vlib.h>

#include <vppinfra/mem.h>

#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

#define SESSION_TIMEOUT	10

#define reverse_direction(direction)	((direction) ^ 0x1)

typedef enum
{
	FLOW_DIRECTION_REVERSE,
	FLOW_DIRECTION_ORIGINAL,
	FLOW_DIRECTION_COUNT
} flow_direction_t;

typedef enum
{
	SESSION_DIRECTION_SERVER_TO_CLIENT,
	SESSION_DIRECTION_CLIENT_TO_SERVER,
	SESSION_DIRECTION_COUNT,
} session_direction_t;

typedef struct
{
	u32 l4_protocol;
	u16 port[FLOW_DIRECTION_COUNT];
	ip4_address_t ip[FLOW_DIRECTION_COUNT];
} flow_key_v4_t;

typedef struct
{
	u32 l4_protocol;
	u16 port[FLOW_DIRECTION_COUNT];
	ip6_address_t ip[FLOW_DIRECTION_COUNT];
} flow_key_v6_t;

typedef struct
{
	CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

	u64 flow_direction : 1;
	u64 session_direction : 1;
	f64 start_time;
	f64 end_time;
	vlib_counter_t counter[FLOW_DIRECTION_COUNT];
	u64 l7_protocol;
	u64 application_id;
	void *transport;

	union
	{
		flow_key_v4_t key_v4;
		flow_key_v6_t key_v6;
		struct
		{
			u32 l4_protocol;
			u16 port[FLOW_DIRECTION_COUNT];
			union
			{
				struct
				{
					ip4_address_t ip4[FLOW_DIRECTION_COUNT];
				};

				struct
				{
					ip6_address_t ip6[FLOW_DIRECTION_COUNT];
				};
			};
		};
	};
} session_t;

typedef struct
{
	flow_direction_t flow_direction;
	session_t *session;
} session_flow_t;

#undef always_inline

#define NAME					session_v4_map
#define KEY_TY					flow_key_v4_t
#define VAL_TY					session_t *
#define HASH_FN(key)			vt_wyhash(&(key), sizeof(KEY_TY))
#define CMPR_FN(key_1, key_2)	memcmp(&(key_1), &(key_2), sizeof(KEY_TY)) == 0
#define MALLOC_FN				clib_mem_alloc
#define FREE_FN(ptr, size)		clib_mem_free(ptr)
#include "verstable.h"

#define NAME					session_v6_map
#define KEY_TY					flow_key_v6_t
#define VAL_TY					session_t *
#define HASH_FN(key)			vt_wyhash(&(key), sizeof(KEY_TY))
#define CMPR_FN(key_1, key_2)	memcmp(&(key_1), &(key_2), sizeof(KEY_TY)) == 0
#define MALLOC_FN				clib_mem_alloc
#define FREE_FN(ptr, size)		clib_mem_free(ptr)
#include "verstable.h"

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

typedef struct
{
	CLIB_CACHE_LINE_ALIGN_MARK (cacheline);
	f64 now;
	session_t *session_pool;
	session_v4_map session_map_v4;
	session_v6_map session_map_v6;
	tw_timer_wheel_1t_3w_1024sl_ov_t time_wheel_v4;
	tw_timer_wheel_1t_3w_1024sl_ov_t time_wheel_v6;
} session_worker_t;

extern __thread session_worker_t *session_worker;

#endif