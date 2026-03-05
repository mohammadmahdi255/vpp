#include "metadata_generator_funcs.h"

#include <vat/vat.h>
#include <vnet/buffer.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/vnet.h>

u8 *
produce_v4_csv_record(u8 *buffer, ipv4_session_t *session)
{
	u64 start_s  = (u64) session->start_time;
	u64 end_s = (u64) session->end_time;
	u64 start_ms = (u64)((session->start_time - (f64) start_s) * 1000);
	u64 end_ms = (u64)((session->end_time - (f64) end_s) * 1000);

	vec_reset_length(buffer);

	return format(buffer,
			"%u,"	/* probe_id */
			"%llu,"			/* start_time_s */
			"%llu,"			/* start_time_ms */
			"%llu,"			/* end_time_s */
			"%llu,"			/* end_time_ms */
			"%U,"			/* src_ip */
			"%u,"			/* src_port */
			"%U,"			/* dst_ip */
			"%u,"			/* dst_port */
			"%u,"			/* l4_protocol */
			"%llu,"			/* packets c2s */
			"%llu,"			/* packets s2c */
			"%llu,"			/* bytes c2s */
			"%llu\n",		/* bytes s2c */
			/* probe_id */
			254,
			/* timestamps */
			start_s,
			start_ms,
			end_s,
			end_ms,
			/* src */
			format_ip4_address, &session->src_ip,
			clib_net_to_host_u16(session->src_port),
			/* dst */
			format_ip4_address, &session->dst_ip,
			clib_net_to_host_u16(session->dst_port),
			/* protocol */
			session->l4_protocol,
			/* counters */
			session->counter[FLOW_DIRECTION_CLIENT_TO_SERVER].packets,
			session->counter[FLOW_DIRECTION_SERVER_TO_CLIENT].packets,
			session->counter[FLOW_DIRECTION_CLIENT_TO_SERVER].bytes,
			session->counter[FLOW_DIRECTION_SERVER_TO_CLIENT].bytes
	);
}

u8 *
produce_v6_csv_record(u8 *buffer, ipv6_session_t *session)
{
	u64 start_s  = (u64) session->start_time;
	u64 end_s = (u64) session->end_time;
	u64 start_ms = (u64)((session->start_time - (f64) start_s) * 1000);
	u64 end_ms = (u64)((session->end_time - (f64) end_s) * 1000);

	vec_reset_length(buffer);

	return format(buffer,
			"%u,"	/* probe_id */
			"%llu,"			/* start_time_s */
			"%llu,"			/* start_time_ms */
			"%llu,"			/* end_time_s */
			"%llu,"			/* end_time_ms */
			"%U,"			/* src_ip */
			"%u,"			/* src_port */
			"%U,"			/* dst_ip */
			"%u,"			/* dst_port */
			"%u,"			/* l4_protocol */
			"%llu,"			/* packets c2s */
			"%llu,"			/* packets s2c */
			"%llu,"			/* bytes c2s */
			"%llu\n",		/* bytes s2c */
			/* probe_id */
			254,
			/* timestamps */
			start_s,
			start_ms,
			end_s,
			end_ms,
			/* src */
			format_ip6_address, &session->src_ip,
			clib_net_to_host_u16(session->src_port),
			/* dst */
			format_ip6_address, &session->dst_ip,
			clib_net_to_host_u16(session->dst_port),
			/* protocol */
			session->l4_protocol,
			/* counters */
			session->counter[FLOW_DIRECTION_CLIENT_TO_SERVER].packets,
			session->counter[FLOW_DIRECTION_SERVER_TO_CLIENT].packets,
			session->counter[FLOW_DIRECTION_CLIENT_TO_SERVER].bytes,
			session->counter[FLOW_DIRECTION_SERVER_TO_CLIENT].bytes
	);
}