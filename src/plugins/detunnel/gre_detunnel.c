#include <stdbool.h>
#include <vlib/vlib.h>

#include <vnet/ethernet/packet.h>
#include <vnet/gre/packet.h>
#include <vnet/vnet.h>

#include <vppinfra/clib.h>

#include "detunnel.h"
#include "vlib/buffer.h"
#include "vppinfra/byte_order.h"

#define foreach_gre_detunnel_next						\
	_(drop_next, DROP, "drop")							\
	_(vlan_next, VLAN_DETUNNEL, "vlan-detunnel")		\
	_(ipv4_next, IPV4_DETUNNEL, "ipv4-detunnel")		\
	_(ipv6_next, IPV6_DETUNNEL, "ipv6-detunnel")		\
	_(mpls_next, MPLS_DETUNNEL, "mpls-detunnel")		\
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
		SIMD_TYPE vlan_mask_vec = (next_vec == SIMD_VEC(vlan_ethertype));
		SIMD_TYPE ipv4_mask_vec = (next_vec == SIMD_VEC(ipv4_ethertype));
		SIMD_TYPE ipv6_mask_vec = (next_vec == SIMD_VEC(ipv6_ethertype));
		SIMD_TYPE mpls_mask_vec = (next_vec == SIMD_VEC(mpls_ethertype));
		SIMD_TYPE failed_mask_vec = (next_vec == SIMD_VEC(invalid_ethertype));

		SIMD_TYPE result = SIMD_VEC(drop_next) |
				(vlan_mask_vec & SIMD_VEC(vlan_next)) |
				(ipv4_mask_vec & SIMD_VEC(ipv4_next)) |
				(ipv6_mask_vec & SIMD_VEC(ipv6_next)) |
				(mpls_mask_vec & SIMD_VEC(mpls_next)) |
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

u16 advance_gre_header(vlib_buffer_t *b)
{
	const gre_header_t* gre = vlib_buffer_get_current(b);
	vlib_buffer_advance(b, sizeof(gre_header_t));

	/*
	 * If either the checksum present bit or the routing present bit are set
	 * both the checksum and offset fields are present in GRE packet
	 */

	const bool checksum_flag = gre->flags_and_version & GRE_FLAGS_CHECKSUM;
	const bool routing_flag = gre->flags_and_version & GRE_FLAGS_ROUTING;
	const bool key_flag = gre->flags_and_version & GRE_FLAGS_KEY;
	const bool sequence_flag = gre->flags_and_version & GRE_FLAGS_SEQUENCE;
	const bool ack_flag = gre->flags_and_version & GRE_FLAGS_ACK;

	u16 size = (checksum_flag | routing_flag + key_flag + sequence_flag) * sizeof(u32);

	switch (gre->protocol)
	{
		case __builtin_bswap16(ETHERNET_TYPE_PPP):
		case __builtin_bswap16(ETHERNET_TYPE_3GPP2):
		case __builtin_bswap16(ETHERNET_TYPE_CDMA_2000):
		{
			// Acknowledgement number
				size += ack_flag * sizeof(u32);
			break;
		}

		case __builtin_bswap16(ETHERNET_TYPE_WCCP):
        {
			/*
			 * WCCP2 puts an extra 4 octets into the header, but uses the same
			 * encapsulation type; if it looks as if the first octet of the packet
			 * isn't the beginning of an IPv4 header, assume it's WCCP2.
			 */
			size += ((*(u8 *) vlib_buffer_get_current(b) & 0xF0) != 0x40) * sizeof(u32);
			break;
        }
		default:
			break;
	}


	// Routing
	while (PREDICT_FALSE(routing_flag))
	{
		const gre_routing_header_t* routing_header = vlib_buffer_get_current(b) + size;
		size += sizeof(gre_routing_header_t) + routing_header->sre_size;

		if (PREDICT_TRUE(routing_header->address_family == 0x0000 && routing_header->sre_size == 0))
			break;

		if (PREDICT_FALSE(vlib_buffer_has_space(b, size)))
			return ETHERNET_TYPE_INVALID;
	}

	vlib_buffer_advance(b, size);
	return gre->protocol;
}

static_always_inline void
process_buffer_4x(vlib_main_t *vm, vlib_node_runtime_t *node,
		vlib_buffer_t* b[4], u16 next[4])
{
	const u32 sw_idx0 = vnet_buffer(b[0])->sw_if_index[VLIB_RX];
	const u32 sw_idx1 = vnet_buffer(b[1])->sw_if_index[VLIB_RX];
	const u32 sw_idx2 = vnet_buffer(b[2])->sw_if_index[VLIB_RX];
	const u32 sw_idx3 = vnet_buffer(b[3])->sw_if_index[VLIB_RX];

	const u8 sw_idx_eq = sw_idx0 == sw_idx1 && sw_idx2 == sw_idx3 && sw_idx0 == sw_idx2;

	const u8 is_valid0 = vlib_buffer_has_space(b[0], sizeof(gre_header_t));
	const u8 is_valid1 = vlib_buffer_has_space(b[1], sizeof(gre_header_t));
	const u8 is_valid2 = vlib_buffer_has_space(b[2], sizeof(gre_header_t));
	const u8 is_valid3 = vlib_buffer_has_space(b[3], sizeof(gre_header_t));

	const u16 bytes0 = is_valid0 ? sizeof(gre_header_t) : 0;
	const u16 bytes1 = is_valid1 ? sizeof(gre_header_t) : 0;
	const u16 bytes2 = is_valid2 ? sizeof(gre_header_t) : 0;
	const u16 bytes3 = is_valid3 ? sizeof(gre_header_t) : 0;

	const gre_header_t *gre0 = vlib_buffer_get_current(b[0]);
	const gre_header_t *gre1 = vlib_buffer_get_current(b[1]);
	const gre_header_t *gre2 = vlib_buffer_get_current(b[2]);
	const gre_header_t *gre3 = vlib_buffer_get_current(b[3]);

	vlib_buffer_advance(b[0], bytes0);
	vlib_buffer_advance(b[1], bytes1);
	vlib_buffer_advance(b[2], bytes2);
	vlib_buffer_advance(b[3], bytes3);

	next[0] = is_valid0 ? gre0->type : ETHERNET_TYPE_INVALID;
	next[1] = is_valid1 ? gre1->type : ETHERNET_TYPE_INVALID;
	next[2] = is_valid2 ? gre2->type : ETHERNET_TYPE_INVALID;
	next[3] = is_valid3 ? gre3->type : ETHERNET_TYPE_INVALID;

	gre_detunnel_main_t *vdm = &gre_detunnel_main;

	if (PREDICT_TRUE(sw_idx_eq))
	{
		vdm->cache_counters[sw_idx0].packets += is_valid0 + is_valid1 + is_valid2 + is_valid3;
		vdm->cache_counters[sw_idx0].bytes += bytes0 + bytes1 + bytes2 + bytes3;
	}
	else
	{
		vdm->cache_counters[sw_idx0].packets += is_valid0;
		vdm->cache_counters[sw_idx1].packets += is_valid1;
		vdm->cache_counters[sw_idx2].packets += is_valid2;
		vdm->cache_counters[sw_idx3].packets += is_valid3;
		vdm->cache_counters[sw_idx0].bytes += bytes0;
		vdm->cache_counters[sw_idx1].bytes += bytes1;
		vdm->cache_counters[sw_idx2].bytes += bytes2;
		vdm->cache_counters[sw_idx3].bytes += bytes3;
	}

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
	{
		add_trace(vm, node, b[0], gre0, is_valid0);
		add_trace(vm, node, b[1], gre1, is_valid1);
		add_trace(vm, node, b[2], gre2, is_valid2);
		add_trace(vm, node, b[3], gre3, is_valid3);
	}
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next)
{
	gre_detunnel_main_t *vdm = &gre_detunnel_main;
	const u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];

	const u8 is_valid = vlib_buffer_has_space(b, sizeof(gre_header_t));
	const u16 bytes = is_valid ? sizeof(gre_header_t) : 0;

	const gre_header_t *gre = vlib_buffer_get_current(b);
	vlib_buffer_advance(b, bytes);

	next[0] = is_valid ? gre->type : ETHERNET_TYPE_INVALID;
	vdm->cache_counters[sw_idx].packets += is_valid;
	vdm->cache_counters[sw_idx].bytes += bytes;

	if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
		add_trace(vm, node, b, gre, is_valid);
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

		process_buffer_4x(vm, node, b, next);

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
	return format(s, "priority_cfi_and_id   0x%04x\n"
			"  ethertype             0x%04x",
			t->gre.priority_cfi_and_id,
			clib_net_to_host_u16(t->gre.type));
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
	SIMD_VEC(vlan_next) = SIMD_SPLAT(GRE_NEXT_VLAN_DETUNNEL);
	SIMD_VEC(ipv4_next) = SIMD_SPLAT(GRE_NEXT_IPV4_DETUNNEL);
	SIMD_VEC(ipv6_next) = SIMD_SPLAT(GRE_NEXT_IPV6_DETUNNEL);
	SIMD_VEC(mpls_next) = SIMD_SPLAT(GRE_NEXT_MPLS_DETUNNEL);
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
