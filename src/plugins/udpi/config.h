#ifndef UDPI_CONFIG_H_
#define UDPI_CONFIG_H_

#include <vlib/vlib.h>

typedef struct
{
	u32 bihash_capacity;
	u32 session_pool_capacity;
} udpi_session_collection_config_t;

typedef struct
{
	void *brokers;
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
	udpi_producer_config_t producer;
} udpi_config_t;

extern const udpi_config_t *udpi_config;

#endif