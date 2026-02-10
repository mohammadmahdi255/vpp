#include <stdbool.h>
#include <vlib/vlib.h>

#include <vnet/ethernet/packet.h>
#include <vnet/gre/packet.h>
#include <vnet/vnet.h>

#include <vppinfra/clib.h>

#include "detunnel.h"
#include "gre/gre.h"
#include "vlib/buffer.h"
#include "vppinfra/byte_order.h"
#include "vppinfra/error.h"

#define foreach_gre_detunnel_next								\
	_(drop_next, DROP, "drop")									\
	_(ethernet_next, ETHERNET_DETUNNEL, "ethernet-detunnel")	\
	_(vlan_next, VLAN_DETUNNEL, "vlan-detunnel")				\
	_(ipv4_next, IPV4_DETUNNEL, "ipv4-detunnel")				\
	_(ipv6_next, IPV6_DETUNNEL, "ipv6-detunnel")				\
	_(mpls_next, MPLS_DETUNNEL, "mpls-detunnel")				\
	_(pppoe_next, PPPOE_DETUNNEL, "pppoe-detunnel")				\
	_(failed_next, FAILED_DETUNNEL, "failed-detunnel")

#define GRE_FLAGS_ACK	(1 << 7)

enum
{
#define _(var, id, name) GRE_NEXT_##id,
	foreach_gre_detunnel_next
#undef _
	GRE_NEXT_N,
};

#define _(var, id, name) static SIMD_TYPE DETUNNEL_CONCAT(var, SIMD_TYPE);

foreach_gre_detunnel_next
#undef _

enum
{
#define _(id, name) GRE_##id,
	foreach_detunnel_counter
#undef _
	GRE_COUNTER_N,
};

typedef struct
{
	gre_header_t gre;
} gre_trace_t;

typedef struct
{
    uint16_t address_family;
    uint8_t sre_offset;
    uint8_t sre_size;
} __clib_packed gre_routing_header_t;

typedef struct
{
	u32 counter_if_index;
	vlib_counter_t cache_counters[MAX_IF_SIZE];
	vlib_combined_counter_main_t counters[GRE_COUNTER_N];
} gre_detunnel_main_t;

extern gre_detunnel_main_t gre_detunnel_main;

static_always_inline void
gre_to_next(u16 *next, u16 len)
{
	for (u16 i = 0; i < len; i += SIMD_SIZE)
	{
		SIMD_TYPE next_vec = SIMD_LOAD(next + i);
		SIMD_TYPE ethernet_mask_vec = (next_vec == SIMD_VEC(eoip_ethertype));
		SIMD_TYPE vlan_mask_vec = (next_vec == SIMD_VEC(vlan_ethertype));
		SIMD_TYPE ipv4_mask_vec = (next_vec == SIMD_VEC(ipv4_ethertype));
		SIMD_TYPE ipv6_mask_vec = (next_vec == SIMD_VEC(ipv6_ethertype));
		SIMD_TYPE mpls_mask_vec = (next_vec == SIMD_VEC(mpls_ethertype));
		SIMD_TYPE pppoe_mask_vec = (next_vec == SIMD_VEC(pppoe_session_ethertype)) |
				(next_vec == SIMD_VEC(pppoe_discovery_ethertype));
		SIMD_TYPE failed_mask_vec = (next_vec == SIMD_VEC(invalid_ethertype));

		SIMD_TYPE result = SIMD_VEC(drop_next) |
				(ethernet_mask_vec & SIMD_VEC(ethernet_next)) |
				(vlan_mask_vec & SIMD_VEC(vlan_next)) |
				(ipv4_mask_vec & SIMD_VEC(ipv4_next)) |
				(ipv6_mask_vec & SIMD_VEC(ipv6_next)) |
				(mpls_mask_vec & SIMD_VEC(mpls_next)) |
				(pppoe_mask_vec & SIMD_VEC(pppoe_next)) |
				(failed_mask_vec & SIMD_VEC(failed_next));

		SIMD_STORE(result, next + i);
	}
}

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		const gre_header_t *gre)
{
	if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) && (b->flags & VLIB_BUFFER_IS_TRACED)))
	{
		gre_trace_t *t = vlib_add_trace(vm, node, b, sizeof(*t));
		t->gre = *gre;
	}
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next)
{
	gre_detunnel_main_t *vdm = &gre_detunnel_main;
	const u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];

	const void *data = vlib_buffer_get_current(b);
	const gre_header_t* gre = data;

	if (PREDICT_FALSE(!vlib_buffer_has_space(b, sizeof(gre_header_t))))
	{
		next[0] = ETHERNET_TYPE_INVALID;
		goto trace;
	}

	/*
	 * If either the checksum present bit or the routing present bit are set
	 * both the checksum and offset fields are present in GRE packet
	 */
	const bool checksum_flag = gre->flags_and_version & clib_host_to_net_u16(GRE_FLAGS_CHECKSUM);
	const bool routing_flag = gre->flags_and_version & clib_host_to_net_u16(GRE_FLAGS_ROUTING);
	const bool key_flag = gre->flags_and_version & clib_host_to_net_u16(GRE_FLAGS_KEY);
	const bool sequence_flag = gre->flags_and_version & clib_host_to_net_u16(GRE_FLAGS_SEQUENCE);
	const bool ack_flag = gre->flags_and_version & clib_host_to_net_u16(GRE_FLAGS_ACK);

	u16 offset = sizeof(gre_header_t) + (checksum_flag | routing_flag + key_flag + sequence_flag) * sizeof(u32);

	switch (gre->protocol)
	{
		case __builtin_bswap16(ETHERNET_TYPE_PPP):
		case __builtin_bswap16(ETHERNET_TYPE_3GPP2):
		case __builtin_bswap16(ETHERNET_TYPE_CDMA_2000):
		{
			// Acknowledgement number
			offset += ack_flag * sizeof(u32);
			break;
		}

		case __builtin_bswap16(ETHERNET_TYPE_WCCP):
        {
			/*
			 * WCCP2 puts an extra 4 octets into the header, but uses the same
			 * encapsulation type; if it looks as if the first octet of the packet
			 * isn't the beginning of an IPv4 header, assume it's WCCP2.
			 */
			offset += ((*(u8 *) (data + offset) & 0xF0) != 0x40) * sizeof(u32);
			break;
        }
		default:
			break;
	}

	// Routing
	while (PREDICT_FALSE(routing_flag))
	{
		const gre_routing_header_t* routing_header = data + offset;
		offset += sizeof(gre_routing_header_t) + routing_header->sre_size;

		if (PREDICT_FALSE(!vlib_buffer_has_space(b, offset)))
		{
			next[0] = ETHERNET_TYPE_INVALID;
			goto trace;
		}

		if (PREDICT_TRUE(routing_header->address_family == 0x0000 && routing_header->sre_size == 0))
			break;
	}

	vlib_buffer_advance(b, offset);
	vdm->cache_counters[sw_idx].packets++;
	vdm->cache_counters[sw_idx].bytes += offset;
	next[0] = gre->protocol;

trace:
	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
		add_trace(vm, node, b, gre);
}

VLIB_NODE_FN (gre_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
	u16 nexts[VLIB_FRAME_SIZE];
	vlib_buffer_t **b = bufs;
	u16 *next = nexts;

	u32 *from = vlib_frame_vector_args(frame);
	u32 n_left_from = frame->n_vectors;

	vlib_get_buffers(vm, from, bufs, n_left_from);

	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	u32 max_sw_if_index = pool_elts(im->sw_interfaces);

	gre_detunnel_main_t *vdm = &gre_detunnel_main;

	if (PREDICT_FALSE(vdm->counter_if_index < max_sw_if_index))
	{
#define _(id, name) vlib_validate_combined_counter(&vdm->counters[GRE_##id], max_sw_if_index);
	foreach_detunnel_counter
#undef _

		for (u32 i = vdm->counter_if_index + 1; i <= max_sw_if_index; i++)
		{
#define _(id, name) vlib_zero_combined_counter(&vdm->counters[GRE_##id], i);
	foreach_detunnel_counter
#undef _
		}

		vdm->counter_if_index = max_sw_if_index;
	}

	while (n_left_from >= 4)
	{
		if (n_left_from >= 8)
		{
			vlib_prefetch_buffer_header(b[4], LOAD);
			vlib_prefetch_buffer_header(b[5], LOAD);
			vlib_prefetch_buffer_header(b[6], LOAD);
			vlib_prefetch_buffer_header(b[7], LOAD);

			vlib_prefetch_buffer_data(b[4], LOAD);
			vlib_prefetch_buffer_data(b[5], LOAD);
			vlib_prefetch_buffer_data(b[6], LOAD);
			vlib_prefetch_buffer_data(b[7], LOAD);
		}

		process_buffer_1x(vm, node, b[0], &next[0]);
		process_buffer_1x(vm, node, b[1], &next[1]);
		process_buffer_1x(vm, node, b[2], &next[2]);
		process_buffer_1x(vm, node, b[3], &next[3]);

		b += 4;
		next += 4;
		n_left_from -= 4;
	}

	while (n_left_from > 0)
	{
		process_buffer_1x(vm, node, b[0], next);

		b++;
		next++;
		n_left_from--;
	}

	for (u32 sw_idx = 0; sw_idx <= max_sw_if_index; sw_idx++)
	{
		vlib_counter_t *counter = &vdm->cache_counters[sw_idx];
		vlib_increment_combined_counter(&vdm->counters[GRE_PROCESSED], vm->thread_index,
				sw_idx, counter->packets, counter->bytes);

		counter->packets = 0;
		counter->bytes = 0;
	}

	gre_to_next(nexts, frame->n_vectors);
	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

#ifndef CLIB_MARCH_VARIANT
gre_detunnel_main_t gre_detunnel_main;

static u8 *format_gre_trace(u8 *s, va_list *args)
{
	vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
	vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
	gre_trace_t *t = va_arg(*args, gre_trace_t *);
	return format (s, "GRE flags_and_version 0x%04x protocol 0x%04x",
			t->gre.flags_and_version, t->gre.protocol);
}

/* Register node */
VLIB_REGISTER_NODE (gre_detunnel) = {
	.name = "gre-detunnel",
	.vector_size = sizeof(u32),
	.format_trace = format_gre_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = GRE_NEXT_N,
	.next_nodes = {
#define _(var, id, name) [GRE_NEXT_##id] = (name),
	foreach_gre_detunnel_next
#undef _
	},
};
#endif

CLIB_MARCH_FN (gre_detunnel_init, clib_error_t *, vlib_main_t __clib_unused *vm)
{
	clib_warning("size: %lu %s", SIMD_SIZE, CLIB_STRING_MACRO(SIMD_TYPE));

	SIMD_VEC(drop_next) = SIMD_SPLAT(GRE_NEXT_DROP);
	SIMD_VEC(ethernet_next) = SIMD_SPLAT(GRE_NEXT_ETHERNET_DETUNNEL);
	SIMD_VEC(vlan_next) = SIMD_SPLAT(GRE_NEXT_VLAN_DETUNNEL);
	SIMD_VEC(ipv4_next) = SIMD_SPLAT(GRE_NEXT_IPV4_DETUNNEL);
	SIMD_VEC(ipv6_next) = SIMD_SPLAT(GRE_NEXT_IPV6_DETUNNEL);
	SIMD_VEC(mpls_next) = SIMD_SPLAT(GRE_NEXT_MPLS_DETUNNEL);
	SIMD_VEC(pppoe_next) = SIMD_SPLAT(GRE_NEXT_PPPOE_DETUNNEL);
	SIMD_VEC(failed_next) = SIMD_SPLAT(GRE_NEXT_FAILED_DETUNNEL);

	return 0;
}

static clib_error_t *gre_detunnel_init(vlib_main_t *vm)
{
	gre_detunnel_main_t *vdm = &gre_detunnel_main;
	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	vdm->counter_if_index = pool_elts(im->sw_interfaces);

#define _(E, n)																\
	vlib_combined_counter_main_t *cm_##n = &vdm->counters[GRE_##E];		\
	cm_##n->name = "gre_" #n;												\
	cm_##n->stat_segment_name = "/detunnel/gre/" #n;						\
	vlib_validate_combined_counter(cm_##n, vdm->counter_if_index);			\
	vlib_zero_combined_counter(cm_##n, vdm->counter_if_index);

	foreach_detunnel_counter
#undef _

	clib_memset(vdm->cache_counters, 0, sizeof(vdm->cache_counters));

	return CLIB_MARCH_FN_SELECT(gre_detunnel_init) (vm);
}

VLIB_INIT_FUNCTION (gre_detunnel_init);
