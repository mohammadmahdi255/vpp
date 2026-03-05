#include "config.h"
#include "vppinfra/vec.h"
#include "vppinfra/vec_bootstrap.h"

#include <sched.h>
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
		if (unformat(&sub_input, "map-capacity %u", &sc->map_capacity))
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

	vec_validate(kc->names, 10);
	vec_validate(kc->values, 10);
	vec_set_len(kc->names, 0);
	vec_set_len(kc->values, 0);

	ASSERT(_vec_len(kc->names) == 0);
	ASSERT(_vec_len(kc->values) == 0);

	void *name = NULL;
	void *value = NULL;

	while (unformat_check_input(&sub_input) != UNFORMAT_END_OF_INPUT)
	{
		if (unformat(&sub_input, "topic %s", &kc->topic))
			continue;

		if (unformat(&sub_input, "%s %s", &name, &value))
		{
			vec_add1(kc->names, name);
			vec_add1(kc->values, value);
			name = NULL;
			value = NULL;
			continue;
		}

		return 0;
	}

	unformat_free(&sub_input);
	return 1;
}

uword
unformat_ip_config(unformat_input_t *input, va_list *args)
{
	udpi_ip_config_t *ic = va_arg(*args, udpi_ip_config_t *);

	unformat_input_t sub_input;
	if (!unformat(input, "%U", unformat_vlib_cli_sub_input, &sub_input))
		return 0;

	while (unformat_check_input(&sub_input) != UNFORMAT_END_OF_INPUT)
	{
		if (unformat(&sub_input, "session-collection %U", unformat_session_collection, &ic->session_collection))
			continue;

		if (unformat(&sub_input, "time-wheel %U", unformat_time_wheel, &ic->time_wheel))
			continue;

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
		if (unformat(input, "ipv4 %U", unformat_ip_config, &uc->ipv4_config))
			continue;

		if (unformat(input, "ipv6 %U", unformat_ip_config, &uc->ipv6_config))
			continue;

		if (unformat(input, "kafka %U", unformat_kafka_config, &uc->kafka))
			continue;

		return clib_error_return(0, "unknown udpi option: '%U'", format_unformat_error, input);
	}

	return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (udpi_config_fn, "udpi");