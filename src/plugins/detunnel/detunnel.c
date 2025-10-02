#include "detunnel.h"

#include <vnet/plugin/plugin.h>

// detunnel_main_t detunnel_main;

static_always_inline clib_error_t *detunnel_worker_init (vlib_main_t *vm)
{
	return 0;
}

static_always_inline clib_error_t *detunnel_init (vlib_main_t *vm)
{
	return 0;
}

VLIB_WORKER_INIT_FUNCTION (detunnel_worker_init);
VLIB_INIT_FUNCTION (detunnel_init);