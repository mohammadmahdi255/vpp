
#include "detunnel.h"
#include "gtpu/gtpu.h"
#include "vnet/ip/ip_packet.h"
#include "vppinfra/error.h"
#include "vppinfra/string.h"

#include <vnet/ethernet/ethernet.h>

#undef always_inline

#include <rte_acl.h>
#include <rte_eal.h>
#include <rte_lcore.h>

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

#define foreach_ethertype	\
	_(vlan_ethertype)		\
	_(ip4_ethertype)		\
	_(ip6_ethertype)

#define foreach_ip_protocol	\
	_(tcp_protocol)			\
	_(udp_protocol)

#define foreach_next_node 	\
	_(vlan_next)			\
	_(ip4_next)				\
	_(ip6_next)				\
	_(udp_next)				\
	_(drop_next)

#ifndef CLIB_MARCH_VARIANT
#define _(name)						\
		u16x32 name##_u16x32;		\
		u16x16 name##_u16x16;		\
		u16x8 name##_u16x8;

foreach_ethertype
foreach_ip_protocol
foreach_next_node
#undef _

struct rte_acl_ctx *transport_to_next;
struct rte_acl_field_def field_defs[TRANSPORT_NUM_FIELDS] = {
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint8_t),
		.field_index = TRANSPORT_FIELD_PROTO,
		.input_index = offsetof(transport_rule_t, proto) >> 2,
		.offset = offsetof(transport_rule_t, proto),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint16_t),
		.field_index = TRANSPORT_FIELD_SRC_PORT,
		.input_index = offsetof(transport_rule_t, src_port) >> 2,
		.offset = offsetof(transport_rule_t, src_port),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint16_t),
		.field_index = TRANSPORT_FIELD_DST_PORT,
		.input_index = offsetof(transport_rule_t, dst_port) >> 2,
		.offset = offsetof(transport_rule_t, dst_port),
	},
};

#else
#define _(name)							\
		extern u16x32 name##_u16x32;	\
		extern u16x16 name##_u16x16;	\
		extern u16x8 name##_u16x8;

foreach_ethertype
foreach_ip_protocol
foreach_next_node
#undef _

extern struct rte_acl_ctx *transport_to_next;
extern struct rte_acl_field_def field_defs[TRANSPORT_NUM_FIELDS];
#endif

CLIB_MARCH_FN (detunnel_init, clib_error_t *, vlib_main_t *CLIB_UNUSED(vm))
{
	clib_warning("size: %lu %s", SIMD_SIZE, STR(SIMD_TYPE));
	SIMD_VEC(vlan_ethertype) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_VLAN));
	SIMD_VEC(ip4_ethertype) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_IP4));
	SIMD_VEC(ip6_ethertype) = SIMD_SPLAT(clib_host_to_net_u16(ETHERNET_TYPE_IP6));

	SIMD_VEC(tcp_protocol) = SIMD_SPLAT(IP_PROTOCOL_TCP);
	SIMD_VEC(udp_protocol) = SIMD_SPLAT(IP_PROTOCOL_UDP);

	SIMD_VEC(drop_next) = SIMD_SPLAT(NEXT_NODE_ERROR_DROP);
	SIMD_VEC(vlan_next) = SIMD_SPLAT(NEXT_NODE_VLAN_DETUNNEL);
	SIMD_VEC(ip4_next) = SIMD_SPLAT(NEXT_NODE_IP4_DETUNNEL);
	SIMD_VEC(ip6_next) = SIMD_SPLAT(NEXT_NODE_IP6_DETUNNEL);
	SIMD_VEC(udp_next) = SIMD_SPLAT(NEXT_NODE_UDP_DETUNNEL);

	return 0;
}

CLIB_MARCH_FN (ethertype_to_next, void, u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE ethertype_vec = SIMD_LOAD(next + i);
		SIMD_TYPE vlan_mask_vec = (ethertype_vec == SIMD_VEC(vlan_ethertype));
		SIMD_TYPE ip4_mask_vec = (ethertype_vec == SIMD_VEC(ip4_ethertype));
		SIMD_TYPE ip6_mask_vec = (ethertype_vec == SIMD_VEC(ip6_ethertype));
		SIMD_TYPE drop_mask_vec = ~(vlan_mask_vec | ip4_mask_vec | ip6_mask_vec);

		SIMD_TYPE result = (vlan_mask_vec & SIMD_VEC(vlan_next)) |
				(ip4_mask_vec & SIMD_VEC(ip4_next)) |
				(ip6_mask_vec & SIMD_VEC(ip6_next)) |
				(drop_mask_vec & SIMD_VEC(drop_next));

		SIMD_STORE(result, next + i);
	}
}

CLIB_MARCH_FN (ip_protocol_to_next, void, u16 *nexts, u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE ip_protocol_vec = SIMD_LOAD(nexts + i);
		SIMD_TYPE tcp_mask_vec = (ip_protocol_vec == SIMD_VEC(tcp_protocol));
		SIMD_TYPE udp_mask_vec = (ip_protocol_vec == SIMD_VEC(udp_protocol));
		SIMD_TYPE drop_mask = ~(tcp_mask_vec | udp_mask_vec);

		SIMD_TYPE result = (tcp_mask_vec & SIMD_VEC(drop_next)) |
				(udp_mask_vec & SIMD_VEC(udp_next)) |
				(drop_mask & SIMD_VEC(drop_next));

		SIMD_STORE(result, nexts + i);
	}
}

#ifndef CLIB_MARCH_VARIANT
u8 *format_detunnel_trace(u8 *s, va_list *args)
{
	vlib_main_t *CLIB_UNUSED(vm)   = va_arg(*args, vlib_main_t *);
	vlib_node_t *CLIB_UNUSED(node) = va_arg(*args, vlib_node_t *);
	detunnel_trace_t *t = va_arg(*args, detunnel_trace_t *);
	return format(s, "%s: if index %u next protocol 0x%04x", t->name, t->sw_if_index, t->next_protocol);
}

#define GTPU_PORT	2152
#define L2TP_PORT	1701

clib_error_t *
detunnel_worker_init(vlib_main_t *CLIB_UNUSED(vm))
{
	if (transport_to_next)
		return 0;

	struct rte_acl_param acl_param = {
		.name = "transport_to_next",
		.socket_id = (int) rte_lcore_to_socket_id(rte_get_main_lcore()),
		.rule_size = RTE_ACL_RULE_SZ(TRANSPORT_NUM_FIELDS),
		.max_rule_num = 1024,
	};

	transport_to_next = rte_acl_create(&acl_param);
	if (!transport_to_next)
		return clib_error_return(0, "failed to create transport to next");

	enum rte_acl_classify_alg alg = RTE_ACL_CLASSIFY_SCALAR;

	if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512F) &&
			rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512BW) &&
			rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512VL))
	{
		if (rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_512) {
			alg = RTE_ACL_CLASSIFY_AVX512X32;
		} else {
			alg = RTE_ACL_CLASSIFY_AVX512X16;
		}
	}
	else if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX2)) {
		alg = RTE_ACL_CLASSIFY_AVX2;
	}
	else if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_SSE4_1))
	{
		alg = RTE_ACL_CLASSIFY_SSE;
	}

	if (rte_acl_set_ctx_classify(transport_to_next, alg))
	{
		rte_acl_free(transport_to_next);
		return clib_error_return(0, "cannot set classify alg: %d", alg);
	}

	RTE_ACL_RULE_DEF(transport_acl_rule, TRANSPORT_NUM_FIELDS);
	struct transport_acl_rule rules[4];
	clib_memset(&rules, 0, sizeof(rules));

	rules[0].data.category_mask = 1;
	rules[0].data.priority = 1;
	rules[0].data.userdata = TRANSPORT_NEXT_GPRS_DETUNNEL;
	rules[0].field[TRANSPORT_FIELD_PROTO].value.u8 = IP_PROTOCOL_UDP;
	rules[0].field[TRANSPORT_FIELD_PROTO].mask_range.u8 = ~0;
	rules[0].field[TRANSPORT_FIELD_SRC_PORT].value.u16 = GTPU_PORT;
	rules[0].field[TRANSPORT_FIELD_SRC_PORT].mask_range.u16 = ~0;
	rules[0].field[TRANSPORT_FIELD_DST_PORT].value.u16 = 0;
	rules[0].field[TRANSPORT_FIELD_DST_PORT].mask_range.u16 = 0;

	rules[1].data.category_mask = 1;
	rules[1].data.priority = 1;
	rules[1].data.userdata = TRANSPORT_NEXT_GPRS_DETUNNEL;
	rules[1].field[TRANSPORT_FIELD_PROTO].value.u8 = IP_PROTOCOL_UDP;
	rules[1].field[TRANSPORT_FIELD_PROTO].mask_range.u8 = ~0;
	rules[1].field[TRANSPORT_FIELD_SRC_PORT].value.u16 = 0;
	rules[1].field[TRANSPORT_FIELD_SRC_PORT].mask_range.u16 = 0;
	rules[1].field[TRANSPORT_FIELD_DST_PORT].value.u16 = GTPU_PORT;
	rules[1].field[TRANSPORT_FIELD_DST_PORT].mask_range.u16 = ~0;

	rules[2].data.category_mask = 1;
	rules[2].data.priority = 1;
	rules[2].data.userdata = TRANSPORT_NEXT_L2TP_DETUNNEL;
	rules[2].field[TRANSPORT_FIELD_PROTO].value.u8 = IP_PROTOCOL_UDP;
	rules[2].field[TRANSPORT_FIELD_PROTO].mask_range.u8 = ~0;
	rules[2].field[TRANSPORT_FIELD_SRC_PORT].value.u16 = L2TP_PORT;
	rules[2].field[TRANSPORT_FIELD_SRC_PORT].mask_range.u16 = ~0;
	rules[2].field[TRANSPORT_FIELD_DST_PORT].value.u16 = 0;
	rules[2].field[TRANSPORT_FIELD_DST_PORT].mask_range.u16 = 0;

	rules[3].data.category_mask = 1;
	rules[3].data.priority = 1;
	rules[3].data.userdata = TRANSPORT_NEXT_L2TP_DETUNNEL;
	rules[3].field[TRANSPORT_FIELD_PROTO].value.u8 = IP_PROTOCOL_UDP;
	rules[3].field[TRANSPORT_FIELD_PROTO].mask_range.u8 = ~0;
	rules[3].field[TRANSPORT_FIELD_SRC_PORT].value.u16 = 0;
	rules[3].field[TRANSPORT_FIELD_SRC_PORT].mask_range.u16 = 0;
	rules[3].field[TRANSPORT_FIELD_DST_PORT].value.u16 = L2TP_PORT;
	rules[3].field[TRANSPORT_FIELD_DST_PORT].mask_range.u16 = ~0;

	if (rte_acl_add_rules(transport_to_next, (struct rte_acl_rule *) rules, 4) < 0)
		return clib_error_return(0, "cannot add transport to next rules");

	struct rte_acl_config acl_config;
	clib_memset(&acl_config, 0, sizeof(acl_config));

	acl_config.num_categories = 1;
	acl_config.num_fields = TRANSPORT_NUM_FIELDS;
	clib_memcpy(acl_config.defs, field_defs, sizeof(field_defs));

	if (rte_acl_build(transport_to_next, &acl_config) != 0)
	{
        rte_acl_free(transport_to_next);
        return clib_error_return(0, "failed to build transport to next");
	}

	return 0;
}

clib_error_t *
detunnel_init(vlib_main_t *vm)
{
	clib_warning("hello");
	// char *rte_eal_init_args[] = {"--in-memory", "--no-telemetry", "--file-prefix", "vpp", "--iova-mode", "pa"};

	// if (rte_eal_init(sizeof(rte_eal_init_args) / sizeof(char *), rte_eal_init_args))
	// 	return clib_error_return(0, "failed to init rte eal");

	transport_to_next = NULL;

	return CLIB_MARCH_FN_SELECT (detunnel_init) (vm);
}

VLIB_WORKER_INIT_FUNCTION (detunnel_worker_init);

VLIB_INIT_FUNCTION (detunnel_init);

#endif