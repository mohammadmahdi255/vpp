#include "producer.h"

#include <vlib/global_funcs.h>
#include <vlib/threads.h>

#include <vppinfra/error.h>
#include <vppinfra/vec.h>

#include "config.h"

static clib_error_t *
producer_worker_init(vlib_main_t __clib_unused *vm)
{
	clib_warning("init %u", vlib_get_thread_index());
	const vlib_thread_main_t *tm = vlib_get_thread_main();
	const u64 *p = hash_get_mem (tm->thread_registrations_by_name, "workers");
	const vlib_thread_registration_t *tr = (const vlib_thread_registration_t *) p[0];
	const producer_main_t *pm = &producer_main;
	const udpi_producer_config_t *pc = &udpi_config->producer;

	const u32 worker_id = vlib_get_thread_index() - tr->first_index;
	producer_worker = tr->count == 0 ? pm->pw : &pm->pw[worker_id];
	producer_worker_t *pw = producer_worker;

	void *name;
	name = format(NULL, "acquire-session-ring-%u", vlib_get_thread_index());
	pw->acquire_session_v4_ring = rte_ring_create(name, pc->ring_capacity,
			(i32) rte_socket_id(),
			RING_F_SP_ENQ | RING_F_SC_DEQ);
	vec_free(name);

	name = format(NULL, "release-session-ring-%u", vlib_get_thread_index());
	pw->release_session_v4_ring = rte_ring_create(name, pc->ring_capacity,
			(i32) rte_socket_id(),
			RING_F_SP_ENQ | RING_F_SC_DEQ);
	vec_free(name);

	if (!pw->acquire_session_v4_ring || !pw->release_session_v4_ring)
		return clib_error_return (0, "failed to create rte_ring for thread %u", vlib_get_thread_index());

	return 0;
}

VLIB_WORKER_INIT_FUNCTION (producer_worker_init);

#ifndef CLIB_MARCH_VARIANT
__thread producer_worker_t *producer_worker = NULL;
producer_main_t producer_main;

static clib_error_t *
producer_init(vlib_main_t *vm)
{
	const vlib_thread_main_t *tm = vlib_get_thread_main();
	const u64 *p = hash_get_mem (tm->thread_registrations_by_name, "workers");
	const vlib_thread_registration_t *tr = (const vlib_thread_registration_t *) p[0];
	const producer_main_t *pm = &producer_main;

	if (tr->count == 0)
	{
		vec_validate(pm->pw, 0);
		producer_worker_init (vm);
	}
	else
	{
		vec_validate(pm->pw, tr->count - 1);
	}

	return 0;
}

VLIB_INIT_FUNCTION (producer_init) = {
	.runs_after = VLIB_INITS("dpdk_config"),
};
#endif