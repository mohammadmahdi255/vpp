#include <vppinfra/clib_error.h>

#include "config.h"
#include "session.h"

#ifndef CLIB_MARCH_VARIANT
__thread session_worker_t *session_worker;
#endif

static clib_error_t *
session_worker_init(vlib_main_t __clib_unused *vm)
{
	session_worker = clib_mem_alloc(sizeof(session_worker_t));
	clib_memset(session_worker, 0, sizeof(session_worker_t));
	const udpi_session_collection_config_t *sc4 = &udpi_config->ipv4_config.session_collection;
	const udpi_session_collection_config_t *sc6 = &udpi_config->ipv6_config.session_collection;
	const udpi_time_wheel_config_t *tc = &udpi_config->ipv4_config.time_wheel;

	session_worker_t *sw = session_worker;
	tw_timer_wheel_1t_3w_1024sl_ov_t *tw4 = &sw->time_wheel_v4;
	tw_timer_wheel_1t_3w_1024sl_ov_t *tw6 = &sw->time_wheel_v6;

	vt_init(&sw->session_map_v4);
	vt_reserve(&sw->session_map_v4,  max_pow2((u64) sc4->map_capacity * 2));

	vt_init(&sw->session_map_v6);
	vt_reserve(&sw->session_map_v6,  max_pow2((u64) sc6->map_capacity * 2));

	tw_timer_wheel_init_1t_3w_1024sl_ov(tw4, NULL, tc->resolution, tc->max_expiration);
	vec_validate_aligned(tw4->expired_timer_handles, tc->max_expiration, CLIB_CACHE_LINE_BYTES);
	vec_set_len(tw4->expired_timer_handles, 0);

	tw_timer_wheel_init_1t_3w_1024sl_ov(tw6, NULL, tc->resolution, tc->max_expiration);
	vec_validate_aligned(tw6->expired_timer_handles, tc->max_expiration, CLIB_CACHE_LINE_BYTES);
	vec_set_len(tw6->expired_timer_handles, 0);

	ASSERT(_vec_len(tw4->expired_timer_handles) == 0);
	ASSERT(_vec_len(tw6->expired_timer_handles) == 0);

	vlib_worker_thread_barrier_check();

	pool_init_fixed(sw->session_pool, sc4->pool_capacity + sc6->pool_capacity);

	if (!sw->session_pool)
		return clib_error_return(0, "failed to create session pool");

	return 0;
}

VLIB_WORKER_INIT_FUNCTION (session_worker_init);


static clib_error_t *
session_main_init(vlib_main_t *vm)
{
	const vlib_thread_main_t *tm = vlib_get_thread_main();
	const u64 *p = hash_get_mem(tm->thread_registrations_by_name, "workers");
	const vlib_thread_registration_t *tr = (vlib_thread_registration_t *) p[0];

	if (tr->count == 0)
		session_worker_init(vm);

	return 0;
}

VLIB_INIT_FUNCTION (session_main_init);