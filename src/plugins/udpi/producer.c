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
	const udpi_time_wheel_config_t *tc4 = &udpi_config->ipv4_config.time_wheel;
	const udpi_time_wheel_config_t *tc6 = &udpi_config->ipv6_config.time_wheel;

	const u32 worker_id = vlib_get_thread_index() - tr->first_index;
	producer_worker = tr->count == 0 ? pm->pw : &pm->pw[worker_id];
	producer_worker_t *pw = producer_worker;

	const u32 ring_capacity = max_pow2(2ULL * clib_max(tc4->max_expiration, tc6->max_expiration));
	clib_warning("producer ring size %u", ring_capacity);

	void *name = format(NULL, "buffer-ring-%u", vlib_get_thread_index());
	pw->buffer_ring = rte_ring_create_elem(name, sizeof(u8 *),
			ring_capacity,
			(i32) rte_socket_id(),
			RING_F_SP_ENQ | RING_F_SC_DEQ);
	vec_free(name);

	vec_validate_aligned(pw->msgs, clib_max(tc4->max_expiration, tc6->max_expiration), CLIB_CACHE_LINE_BYTES);
	vec_set_len(pw->msgs, 0);

	ASSERT(_vec_len(pw->msgs) == 0);

	if (!pw->buffer_ring)
		return clib_error_return (0, "failed to create rte_ring for thread %u", vlib_get_thread_index());

	for (u32 i = 1; i < ring_capacity; i++)
	{
		u8 *buffer = NULL;
		vec_validate_aligned(buffer, 1 << 8, CLIB_CACHE_LINE_BYTES);
		const i32 rv = rte_ring_sp_enqueue(pw->buffer_ring, buffer);

		if (PREDICT_FALSE(rv))
			clib_error("failed to enqueue to ring buffer");
	}

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

VLIB_INIT_FUNCTION (producer_init);
#endif