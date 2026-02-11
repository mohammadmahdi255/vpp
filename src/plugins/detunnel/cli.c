#include <vlib/vlib.h>

#include <vnet/feature/feature.h>
#include <vnet/global_funcs.h>
#include <vnet/interface_funcs.h>
#include <vnet/vnet.h>

#include <vppinfra/clib.h>
#include <vppinfra/error.h>

extern void ethernet_detunnel_counter_validate(u32 sw_if_index);
extern void gre_detunnel_counter_validate(u32 sw_if_index);
extern void gtpu_detunnel_counter_validate(u32 sw_if_index);
extern void ipv4_detunnel_counter_validate(u32 sw_if_index);
extern void ipv6_detunnel_counter_validate(u32 sw_if_index);
extern void l2tp_detunnel_counter_validate(u32 sw_if_index);
extern void udp_detunnel_counter_validate(u32 sw_if_index);
extern void vlan_detunnel_counter_validate(u32 sw_if_index);

static clib_error_t *
set_interface_detunnel_command_fn(vlib_main_t __clib_unused *vm, unformat_input_t *input,
		vlib_cli_command_t __clib_unused *cmd)
{
	i32 rv = 0;
	u32 sw_if_index = ~0;
	char *arc_name = NULL;
	u8 enable = 1;
	vnet_main_t *vnm = vnet_get_main();

	while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
	{
		if (unformat(input, "disable"))
			enable = 0;
		else if (unformat(input, "%U arc %s", unformat_vnet_sw_interface, vnm, &sw_if_index, &arc_name))
			;
		else
			return clib_error_return(0, "unknown input `%U`", format_unformat_error, input);
	}

	if (!arc_name)
        return clib_error_return(0, "please specify arc");

	if (sw_if_index == ~0)
	{
		vec_free(arc_name);
		return clib_error_return(0, "please specify interface");
	}

	rv = vnet_feature_enable_disable(arc_name, "ethernet-detunnel", sw_if_index, enable, 0, 0);

	if (rv)
	{
		vec_free(arc_name);
		return clib_error_return(0, "failed to enable deunnel feature on arc %s", arc_name);
	}

	ethernet_detunnel_counter_validate(sw_if_index);
	gre_detunnel_counter_validate(sw_if_index);
	gtpu_detunnel_counter_validate(sw_if_index);
	ipv4_detunnel_counter_validate(sw_if_index);
	ipv6_detunnel_counter_validate(sw_if_index);
	l2tp_detunnel_counter_validate(sw_if_index);
	udp_detunnel_counter_validate(sw_if_index);
	vlan_detunnel_counter_validate(sw_if_index);

	return 0;
}

VLIB_CLI_COMMAND (set_interface_detunnel_command, static) = {
	.path = "set interface detunnel",
	.short_help = "set interface detunnel <interface> arc <arc_name> [disable]",
	.function = set_interface_detunnel_command_fn,
};
