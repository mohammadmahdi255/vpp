#include <vlib/vlib.h>

#include <vnet/feature/feature.h>
#include <vnet/global_funcs.h>
#include <vnet/interface_funcs.h>
#include <vnet/vnet.h>

#include <vppinfra/clib.h>
#include <vppinfra/error.h>


static clib_error_t *
set_interface_udpi_command_fn(vlib_main_t __clib_unused *vm, unformat_input_t *input,
		vlib_cli_command_t __clib_unused *cmd)
{
	i32 rv = 0;
	u32 sw_if_index = ~0;
	char *arc_name = NULL;
	char *node_name = NULL;
	u8 enable = 1;
	vnet_main_t *vnm = vnet_get_main();
	clib_error_t *err = NULL;

	while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
	{
		if (unformat(input, "disable"))
		{
			enable = 0;
			continue;
		}

		if (unformat(input, "%U arc %s node %s", unformat_vnet_sw_interface, vnm, &sw_if_index, &arc_name, &node_name))
			continue;

		err = clib_error_return(0, "unknown input `%U`", format_unformat_error, input);
		goto finalize;
	}

	if (!arc_name || !node_name)
	{
        err = clib_error_return(0, "please specify arc");
		goto finalize;
	}

	if (sw_if_index == ~0)
	{
		err = clib_error_return(0, "please specify interface");
		goto finalize;
	}

	rv = vnet_feature_enable_disable(arc_name, node_name, sw_if_index, enable, 0, 0);

	if (rv)
		err = clib_error_return(0, "failed to enable deunnel feature on arc %s", arc_name);

finalize:
	vec_free(arc_name);
	vec_free(node_name);
	return err;
}

VLIB_CLI_COMMAND (set_interface_udpi_command, static) = {
	.path = "set interface udpi",
	.short_help = "set interface udpi <interface> arc <arc_name> node <node_name> [disable]",
	.function = set_interface_udpi_command_fn,
};
