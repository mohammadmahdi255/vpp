#ifndef UDPI_IP_SESSION_H_
#define UDPI_IP_SESSION_H_

#include "vlib/counter_types.h"
#include <vlib/vlib.h>

#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

#define ip_session_template_fields(key_type, ip_type)			\
	union {														\
		key_type key;											\
		struct {												\
			ip_type src_ip;										\
			ip_type dst_ip;										\
			u16 src_port;										\
			u16 dst_port;										\
			u8 l4_protocol;										\
		};														\
	};															\
	f64 start_time;												\
	f64 end_time;												\
	vlib_counter_t counter[FLOW_DIRECTION_COUNT];				\
	u64 l7_protocol;											\
	u64 application_id;											\
	u64 session_id;

#define SESSION_TIMEOUT	1.0

typedef enum
{
	FLOW_DIRECTION_SERVER_TO_CLIENT,
	FLOW_DIRECTION_CLIENT_TO_SERVER,
	FLOW_DIRECTION_COUNT
} flow_direction_t;

typedef union
{
	struct
	{
		u32 index;
		flow_direction_t direction;
	};
	u64 as_u64;
} session_flow_t;

typedef struct
{
	ip4_address_t src_ip;
	ip4_address_t dst_ip;
	u16 src_port;
	u16 dst_port;
	u32 l4_protocol;
} ipv4_flow_key_t;

typedef struct
{
	ip6_address_t src_ip;
	ip6_address_t dst_ip;
	u16 src_port;
	u16 dst_port;
	u32 l4_protocol;
} ipv6_flow_key_t;

typedef struct
{
	CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
	ip_session_template_fields(ipv4_flow_key_t, ip4_address_t);
} ipv4_session_t;


typedef struct
{
	CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
	ip_session_template_fields(ipv6_flow_key_t, ip6_address_t);
} ipv6_session_t;


#define NAME session_v4
#define KEY_TYPE ipv4_flow_key_t
#define VALUE_TYPE ipv4_session_t
#include "boost_flat_map_template.h"

#endif