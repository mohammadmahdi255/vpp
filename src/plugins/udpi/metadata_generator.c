#include <vat/vat.h>
#include <vnet/buffer.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/vnet.h>

#include "ip_session.h"

static u8 *
format_session_id(u8 *s, va_list *args)
{
	void *key = va_arg(*args, void *);
	u32 len = va_arg(*args, u32);
	f64 unix_ts = va_arg(*args, f64);

	return format(s, "%llu", vt_wymix(vt_wyhash(key, len), (u64) unix_ts));
}

static u8 *
format_unix_time(u8 *s, va_list *args)
{
	f64 unix_ts = va_arg(*args, f64);
	u64 sec = (u64) unix_ts;
	u64 ms = (u64)((unix_ts - (f64) sec) * 1000);

	return format(s, "%llu,%llu", sec, ms);
}

u8 *
produce_v4_csv_record(const vlib_main_t* vm, const ipv4_session_t *session, u8 *buffer)
{
	const clib_time_t *ct = &vm->clib_time;

	f64 unix_start = session->start_time + ct->init_reference_time;
	f64 unix_end = session->end_time + ct->init_reference_time;

	vec_reset_length(buffer);

	return format(buffer,
			"%u,"	/* probe_id */
			"%U,"			/* session id */
			"%U,"			/* start_time */
			"%U,"			/* end_time */
			"%U,"			/* src_ip */
			"%u,"			/* src_port */
			"%U,"			/* dst_ip */
			"%u,"			/* dst_port */
			"%u,"			/* l4_protocol */
			"%llu,"			/* packets c2s */
			"%llu,"			/* packets s2c */
			"%llu,"			/* bytes c2s */
			"%llu",		/* bytes s2c */
			/* probe_id */
			254,
			/* session id */
			format_session_id, &session->key, sizeof(session->key), unix_start,
			/* timestamps */
			format_unix_time, unix_start,
			format_unix_time, unix_end,
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
produce_v6_csv_record(const vlib_main_t* vm, const ipv6_session_t *session, u8 *buffer)
{
	const clib_time_t *ct = &vm->clib_time;

	f64 unix_start = session->start_time + ct->init_reference_time;
	f64 unix_end = session->end_time + ct->init_reference_time;

	vec_reset_length(buffer);

	return format(buffer,
			"%u,"	/* probe_id */
			"%U,"			/* session id */
			"%U,"			/* start_time */
			"%U,"			/* end_time */
			"%U,"			/* src_ip */
			"%u,"			/* src_port */
			"%U,"			/* dst_ip */
			"%u,"			/* dst_port */
			"%u,"			/* l4_protocol */
			"%llu,"			/* packets c2s */
			"%llu,"			/* packets s2c */
			"%llu,"			/* bytes c2s */
			"%llu",		/* bytes s2c */
			/* probe_id */
			254,
			/* session id */
			format_session_id, &session->key, sizeof(session->key), unix_start,
			/* timestamps */
			format_unix_time, unix_start,
			format_unix_time, unix_end,
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