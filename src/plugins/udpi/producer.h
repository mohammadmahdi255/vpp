#ifndef UDPI_PRODUCER_H_
#define UDPI_PRODUCER_H_

#include <vlib/vlib.h>

#include <vnet/ip/ip46_address.h>

#include <librdkafka/rdkafka.h>


#undef always_inline

#include <rte_lcore.h>
#include <rte_ring.h>

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

typedef struct
{
	CLIB_CACHE_LINE_ALIGN_MARK (cacheline);

	struct rte_ring *buffer_ring;
	rd_kafka_message_t *msgs;
} producer_worker_t;

typedef struct
{
	producer_worker_t *producer_worker;

	rd_kafka_t *kafka;
	rd_kafka_topic_t *kafka_topic;
} producer_main_t;

extern __thread producer_worker_t *producer_worker;
extern producer_main_t producer_main;

#endif