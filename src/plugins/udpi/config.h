#ifndef UDPI_CONFIG_H_
#define UDPI_CONFIG_H_

#include <vlib/vlib.h>

typedef struct
{
	u32 bihash_capacity;
	u32 pool_capacity;
} udpi_session_collection_config_t;

typedef struct
{
	u32 max_expiration;
	f64 interval;
} udpi_time_wheel_config_t;

typedef struct
{
	void *broker;
	void *topic;
	u32 linger_ms;
	u32 batch_size;
} udpi_kafka_config_t;

typedef struct
{
	udpi_kafka_config_t kafka;
	u32 ring_capacity;
} udpi_producer_config_t;

typedef struct
{
	udpi_session_collection_config_t session_collection;
	udpi_time_wheel_config_t time_wheel;
	udpi_producer_config_t producer;
} udpi_config_t;

extern const udpi_config_t *udpi_config;

#endif