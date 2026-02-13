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
} ipv4_flow_key_t;

typedef struct
{
	ipv4_flow_key_t key;
} ipv4_session_t;

#endif