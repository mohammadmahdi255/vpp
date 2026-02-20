#ifndef UDPI_CONFIG_H_
#define UDPI_CONFIG_H_

#include <vlib/vlib.h>

typedef struct
{
	u32 bihash_total_entries;
	u32 session_pool_size;
} udpi_session_collection_config_t;

typedef struct
{
	udpi_session_collection_config_t session_collection;
} udpi_config_t;

extern udpi_config_t udpi_config;

#endif