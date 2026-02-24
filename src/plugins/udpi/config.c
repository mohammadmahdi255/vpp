#include "config.h"

#include <vlib/vlib.h>

#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>

static udpi_config_t _udpi_config;
const udpi_config_t *udpi_config = &_udpi_config;

uword
unformat_session_collection(unformat_input_t *input, va_list *args)
{
	udpi_session_collection_config_t *sc = va_arg(*args, udpi_session_collection_config_t *);

	unformat_input_t sub_input;
	if (!unformat(input, "%U", unformat_vlib_cli_sub_input, &sub_input))
		return 0;

	while (unformat_check_input(&sub_input) != UNFORMAT_END_OF_INPUT)
	{
		if (unformat(&sub_input, "bihash-capacity %u", &sc->bihash_capacity))
			continue;

		if (unformat(&sub_input, "pool-capacity %u", &sc->pool_capacity))
			continue;

		return 0;
	}

	unformat_free(&sub_input);
	return 1;
}

uword
unformat_time_wheel(unformat_input_t *input, va_list *args)
{
	udpi_time_wheel_config_t *tc = va_arg(*args, udpi_time_wheel_config_t *);

	unformat_input_t sub_input;
	if (!unformat(input, "%U", unformat_vlib_cli_sub_input, &sub_input))
		return 0;

	while (unformat_check_input(&sub_input) != UNFORMAT_END_OF_INPUT)
	{
		if (unformat(&sub_input, "max-expiration %u", &tc->max_expiration))
			continue;

		if (unformat(&sub_input, "interval %f", &tc->interval))
			continue;

		if (unformat(&sub_input, "resolution %f", &tc->resolution))
			continue;

		return 0;
	}

	unformat_free(&sub_input);
	return 1;
}


uword
unformat_kafka_config(unformat_input_t *input, va_list __clib_unused *args)
{
	udpi_kafka_config_t *kc = va_arg(*args, udpi_kafka_config_t *);

	unformat_input_t sub_input;
	if (!unformat(input, "%U", unformat_vlib_cli_sub_input, &sub_input))
		return 0;

	while (unformat_check_input(&sub_input) != UNFORMAT_END_OF_INPUT)
	{
		if (unformat(&sub_input, "broker %s", &kc->broker))
			continue;

		if (unformat (&sub_input, "topic %s", &kc->topic))
			continue;

		if (unformat (&sub_input, "linger-ms %u", &kc->linger_ms))
			continue;

		if (unformat (&sub_input, "batch-size %u", &kc->batch_size))
			continue;

		return 0;
	}

	unformat_free(&sub_input);
	return 1;
}

uword
unformat_producer_config(unformat_input_t *input, va_list __clib_unused *args)
{
	udpi_producer_config_t *pc = va_arg(*args, udpi_producer_config_t *);

	unformat_input_t sub_input;
	if (!unformat(input, "%U", unformat_vlib_cli_sub_input, &sub_input))
		return 0;

	while (unformat_check_input(&sub_input) != UNFORMAT_END_OF_INPUT)
	{
		if (unformat(&sub_input, "kafka %U", unformat_kafka_config, &pc->kafka))
			continue;

		if (unformat(&sub_input, "ring-capacity %u", &pc->ring_capacity))
		{
			pc->ring_capacity = max_pow2(pc->ring_capacity);
			continue;
		}

		return 0;
	}

	unformat_free(&sub_input);
	return 1;
}

static clib_error_t *
udpi_config_fn (vlib_main_t __clib_unused *vm, unformat_input_t *input)
{
	udpi_config_t *uc = &_udpi_config;

	while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
	{
		if (unformat(input, "session-collection %U", unformat_session_collection, &uc->session_collection))
			continue;

		if (unformat(input, "time-wheel %U", unformat_time_wheel, &uc->time_wheel))
			continue;

		if (unformat(input, "producer %U", unformat_producer_config, &uc->producer))
			continue;

		return clib_error_return (0, "unknown udpi option: '%U'", format_unformat_error, input);
	}

	return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (udpi_config_fn, "udpi");