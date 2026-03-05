#ifndef UDPI_CONFIG_H_
#define UDPI_CONFIG_H_

#include <vlib/vlib.h>

typedef struct
{
	u32 map_capacity;
	u32 pool_capacity;
} udpi_session_collection_config_t;

typedef struct
{
	u32 max_expiration;
	f64 interval;
	f64 resolution;
} udpi_time_wheel_config_t;

typedef struct
{
	udpi_session_collection_config_t session_collection;
	udpi_time_wheel_config_t time_wheel;
} udpi_ip_config_t;

typedef struct
{
	void *topic;
	void **names;
	void **values;
} udpi_kafka_config_t;

typedef struct
{
	udpi_ip_config_t ipv4_config;
	udpi_ip_config_t ipv6_config;
	udpi_kafka_config_t kafka;
} udpi_config_t;

extern const udpi_config_t *udpi_config;

#endif