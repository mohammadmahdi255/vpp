#include "producer.h"

#include <vlib/global_funcs.h>
#include <vlib/threads.h>

#include <vppinfra/error.h>
#include <vppinfra/vec.h>

#include "config.h"
#include "rte_ring_elem.h"
#include "vppinfra/cache.h"
#include "vppinfra/clib.h"
#include "vppinfra/mem.h"

#ifndef CLIB_MARCH_VARIANT
__thread producer_worker_t *producer_worker = NULL;
producer_main_t producer_main;
#endif

static_always_inline clib_error_t *
producer_worker_init(vlib_main_t __clib_unused *vm)
{
	const vlib_thread_main_t *tm = vlib_get_thread_main();
	const u64 *p = hash_get_mem (tm->thread_registrations_by_name, "workers");
	const vlib_thread_registration_t *tr = (const vlib_thread_registration_t *) p[0];
	const producer_main_t *pm = &producer_main;
	const udpi_time_wheel_config_t *tc4 = &udpi_config->ipv4_config.time_wheel;
	const udpi_time_wheel_config_t *tc6 = &udpi_config->ipv6_config.time_wheel;

	const u32 worker_id = vlib_get_thread_index() - tr->first_index;
	producer_worker = tr->count == 0 ? pm->producer_worker : &pm->producer_worker[worker_id];
	producer_worker_t *pw = producer_worker;

	const u32 ring_capacity = max_pow2(2ULL * clib_max(tc4->max_expiration, tc6->max_expiration));
	const u64 ring_memsize = rte_ring_get_memsize_elem(sizeof(u8 *), ring_capacity);

	pw->buffer_ring = (struct rte_ring *) clib_mem_alloc_aligned(ring_memsize, CLIB_CACHE_LINE_BYTES);

	void *name = format(NULL, "buffer-ring-%u", vlib_get_thread_index());
	const i32 rv = rte_ring_init(pw->buffer_ring, name, ring_capacity, RING_F_SP_ENQ | RING_F_SC_DEQ);
	vec_free(name);

	if (PREDICT_FALSE(rv))
		return clib_error_return(0, "failed to create rte_ring for thread %u", vlib_get_thread_index());

	vec_validate_aligned(pw->msgs, clib_max(tc4->max_expiration, tc6->max_expiration), CLIB_CACHE_LINE_BYTES);
	vec_set_len(pw->msgs, 0);

	ASSERT(_vec_len(pw->msgs) == 0);

	for (u32 i = 1; i < ring_capacity; i++)
	{
		u8 *buffer = NULL;
		vec_validate_aligned(buffer, 1 << 8, CLIB_CACHE_LINE_BYTES);
		const i32 rv = rte_ring_sp_enqueue(pw->buffer_ring, buffer);

		if (PREDICT_FALSE(rv))
			return clib_error_return(0, "failed to enqueue to buffer ring");
	}

	return 0;
}

static_always_inline clib_error_t *
producer_init(vlib_main_t *vm)
{
	const vlib_thread_main_t *tm = vlib_get_thread_main();
	const u64 *p = hash_get_mem(tm->thread_registrations_by_name, "workers");
	const vlib_thread_registration_t *tr = (const vlib_thread_registration_t *) p[0];
	const producer_main_t *pm = &producer_main;

	if (tr->count == 0)
	{
		vec_validate(pm->producer_worker, 0);
		return producer_worker_init(vm);
	}

	vec_validate(pm->producer_worker, tr->count - 1);
	return 0;
}

static_always_inline clib_error_t *
producer_exit(vlib_main_t __clib_unused *vm)
{
	producer_main_t *pm = &producer_main;
	producer_worker_t *pw = NULL;
	rd_kafka_message_t *msg = NULL;

	vec_foreach(pw, pm->producer_worker)
	{
		while (!rte_ring_empty(pw->buffer_ring))
		{
			u8 *buffer = NULL;
			const i32 rv = rte_ring_sc_dequeue(pw->buffer_ring, (void **) &buffer);

			if (PREDICT_FALSE(rv))
				return clib_error_return(0, "failed to dequque from buffer ring");

			vec_free(buffer);
		}

		vec_foreach(msg, pw->msgs)
		{
			vec_free(msg->payload);
		}

		vec_free(pw->msgs);
		clib_mem_free(pw->buffer_ring);
		pw->buffer_ring = NULL;
	}

	vec_free(pm->producer_worker);

	return 0;
}

static_always_inline clib_error_t *
show_producer_stats_fn(vlib_main_t *vm, unformat_input_t __clib_unused *input,
						 vlib_cli_command_t __clib_unused *cmd)
{
	const producer_main_t *pm = &producer_main;
	const udpi_kafka_config_t *kc = &udpi_config->kafka;
	u32 i;

	vlib_cli_output(vm, "topic:       %s", kc->topic);

	vec_foreach_index(i, pm->producer_worker)
		vlib_cli_output(vm, "buffer ring [%u] count=%u", i, rte_ring_count(pm->producer_worker[i].buffer_ring));

	return 0;
}

VLIB_CLI_COMMAND (producer_show_stats_cmd, static) = {
	.path = "show producer stats",
	.short_help = "show producer statistics",
	.function = show_producer_stats_fn,
};

VLIB_WORKER_INIT_FUNCTION (producer_worker_init);
VLIB_INIT_FUNCTION (producer_init);
VLIB_MAIN_LOOP_EXIT_FUNCTION (producer_exit);