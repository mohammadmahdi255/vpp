#include <vlib/vlib.h>

#include <vppinfra/vec.h>

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
	struct rte_ring *acquire_session_ring;
	struct rte_ring *release_session_ring;
} producer_worker_t;

typedef struct
{
	producer_worker_t *pw;
} producer_main_t;

extern __thread producer_worker_t *producer_worker;
extern producer_main_t producer_main;

#ifndef CLIB_MARCH_VARIANT
__thread producer_worker_t *producer_worker;
producer_main_t producer_main;
#endif

static clib_error_t *
producer_worker_init (vlib_main_t __clib_unused *vm)
{
	const u32 thread_id = vlib_get_thread_index ();
	producer_main_t *pm = &producer_main;

	vec_validate (pm->pw, thread_id);
	producer_worker = &pm->pw[thread_id];
	producer_worker_t *pw = producer_worker;

	/* size must be power of 2 */
	const u32 max_ring_size = 1 << 16;

	void *name;

	name = format(NULL, "acquire-session-ring-%u", thread_id);
	pw->acquire_session_ring = rte_ring_create(name, max_ring_size,
			(i32) rte_socket_id(),
			RING_F_SP_ENQ | RING_F_SC_DEQ);
	vec_free(name);

	name = format(NULL,  "release-session-ring-%u", thread_id);
	pw->release_session_ring = rte_ring_create(name, max_ring_size,
			(i32) rte_socket_id(),
			RING_F_SP_ENQ | RING_F_SC_DEQ);
	vec_free(name);

	if (!pw->acquire_session_ring || !pw->release_session_ring)
		return clib_error_return (0, "failed to create rte_ring for thread %u", thread_id);

	return 0;
}

static clib_error_t *
producer_init (vlib_main_t *vm)
{
	const vlib_thread_main_t *tm = vlib_get_thread_main ();
	const u64 *p = hash_get_mem (tm->thread_registrations_by_name, "workers");
	const vlib_thread_registration_t *tr = (const vlib_thread_registration_t *) p[0];

	if (tr->count == 0)
		producer_worker_init (vm);

	return 0;
}

VLIB_WORKER_INIT_FUNCTION (producer_worker_init);
VLIB_INIT_FUNCTION (producer_init);