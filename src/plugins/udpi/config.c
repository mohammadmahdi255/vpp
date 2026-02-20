#include "config.h"

#include <vlib/vlib.h>

#include <vppinfra/format.h>

udpi_config_t udpi_config;

uword
unformat_session_collection(unformat_input_t *input, va_list __clib_unused *args)
{
	udpi_session_collection_config_t *sc = &udpi_config.session_collection;

	unformat_input_t sub_input;
	if (!unformat(input, "%U", unformat_vlib_cli_sub_input, &sub_input))
		return 0;

	while (unformat_check_input(&sub_input) != UNFORMAT_END_OF_INPUT)
	{
		if (unformat(&sub_input, "bihash-total-entries %u", &sc->bihash_total_entries))
			continue;

		if (unformat(&sub_input, "session-pool-size %u", &sc->session_pool_size))
			continue;

		return 0;
	}

	unformat_free (&sub_input);
	return 1;
}

static clib_error_t *
udpi_config_fn (vlib_main_t __clib_unused *vm, unformat_input_t *input)
{
	while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
	{
		if (unformat(input, "session-collection %U", unformat_session_collection))
			continue;

		return clib_error_return (0, "unknown udpi option: '%U'", format_unformat_error, input);
	}

	return 0;
}

VLIB_CONFIG_FUNCTION (udpi_config_fn, "udpi");