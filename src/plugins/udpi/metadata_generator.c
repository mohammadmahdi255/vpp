#include <vat/vat.h>
#include <vnet/buffer.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/vnet.h>

#include "session.h"
#include "udpi/session_inlines.h"

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
produce_v4_csv_record(const vlib_main_t* vm, const session_t *session, u8 *buffer)
{
	const clib_time_t *ct = &vm->clib_time;

	f64 unix_start = session->start_time + ct->init_reference_time;
	f64 unix_end = session->end_time + ct->init_reference_time;

	session_direction_t c2s = session->session_direction;
	session_direction_t s2c = reverse_direction(c2s);

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
			format_session_id, &session->key_v4, sizeof(session->key_v4), unix_start,
			/* timestamps */
			format_unix_time, unix_start,
			format_unix_time, unix_end,
			/* src */
			format_ip4_address, &session->ip4[c2s],
			clib_net_to_host_u16(session->port[c2s]),
			/* dst */
			format_ip4_address, &session->ip4[s2c],
			clib_net_to_host_u16(session->port[s2c]),
			/* protocol */
			session->l4_protocol,
			/* counters */
			session->counter[c2s].packets,
			session->counter[s2c].packets,
			session->counter[c2s].bytes,
			session->counter[s2c].bytes
	);
}

u8 *
produce_v6_csv_record(const vlib_main_t* vm, const session_t *session, u8 *buffer)
{
	const clib_time_t *ct = &vm->clib_time;

	f64 unix_start = session->start_time + ct->init_reference_time;
	f64 unix_end = session->end_time + ct->init_reference_time;

	session_direction_t c2s = session->session_direction;
	session_direction_t s2c = reverse_direction(c2s);

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
			format_session_id, &session->key_v6, sizeof(session->key_v6), unix_start,
			/* timestamps */
			format_unix_time, unix_start,
			format_unix_time, unix_end,
			/* src */
			format_ip6_address, &session->ip6[c2s],
			clib_net_to_host_u16(session->port[c2s]),
			/* dst */
			format_ip6_address, &session->ip6[s2c],
			clib_net_to_host_u16(session->port[s2c]),
			/* protocol */
			session->l4_protocol,
			/* counters */
			session->counter[c2s].packets,
			session->counter[s2c].packets,
			session->counter[c2s].bytes,
			session->counter[s2c].bytes
	);
}