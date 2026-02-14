#ifndef UDPI_IPV4_SESSION_H_
#define UDPI_IPV4_SESSION_H_

#include "vlib/counter_types.h"
#include <vlib/vlib.h>

#include <vnet/ip/ip4_packet.h>

typedef enum
{
	FLOW_DIRECTION_CLIENT_TO_SERVER,
	FLOW_DIRECTION_SERVER_TO_CLIENT,
	FLOW_DIRECTION_COUNT
} flow_direction_t;

typedef struct
{
	ip4_address_t src_ip;
	ip4_address_t dst_ip;
	u16 src_port;
	u16 dst_port;
	u8 l4_protocol;
} ipv4_flow_key_t;

typedef struct
{
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
	ipv4_flow_key_t key;
	struct timeval start_time;
	struct timeval end_time;
	vlib_counter_t counter[FLOW_DIRECTION_CLIENT_TO_SERVER];
	u64 l7_protocol;
    u64 application_id;
	u64 session_id;
} ipv4_session_t;

#endif