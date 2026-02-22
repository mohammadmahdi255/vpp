#ifndef UDPI_PRODUCER_H_
#define UDPI_PRODUCER_H_

#include <vlib/vlib.h>

#include <vnet/ip/ip46_address.h>

#undef always_inline

#include <rte_lcore.h>
#include <rte_ring.h>

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

typedef struct
{
	struct rte_ring *acquire_session_v4_ring;
	struct rte_ring *release_session_v4_ring;
	struct rte_ring *acquire_session_v6_ring;
	struct rte_ring *release_session_v6_ring;
} producer_worker_t;

typedef struct
{
	producer_worker_t *pw;
} producer_main_t;

extern __thread producer_worker_t *producer_worker;
extern producer_main_t producer_main;

#endif