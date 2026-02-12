#ifndef UDPI_IPV4_SESSION_H_
#define UDPI_IPV4_SESSION_H_

#include <vlib/vlib.h>

#include <vnet/ip/ip4_packet.h>

typedef struct
{
	ip4_address_t src_addr;
	ip4_address_t dst_addr;
	u16 src_port;
	u16 dst_port;
	u8 protocol;
} ipv4_5tuple_key_t;

// Session data structure
typedef struct
{
	ipv4_5tuple_key_t key;
	u64 session_id;
	u64 packet_count;
	u64 byte_count;
	f64 first_seen;
	f64 last_seen;
	u32 session_index;
	u8 flags;
} ipv4_session_t;

#endif