#include <librdkafka/rdkafka.h>

#include <svm/fifo_types.h>

#include <vppinfra/cpu.h>
#include <vppinfra/format.h>
#include <vppinfra/mem.h>
#include <vppinfra/vec.h>

typedef struct
{
	// Worker rings
	producer_worker_ring_t *worker_rings;
	u32 num_workers;
	u64 producer_worker_ring_size;
	u32 ring_dequeue_threshold;

	u64 counters[UDPI_PRODUCER_N_COUNTERS];
	vlib_simple_counter_main_t *udpi_producer_simple_counters;

} kafka_producer_main_t;

kafka_producer_main_t kafka_producer_main;

producer_ring_buffer_t *
producer_ring_buffer_create(u64 size)
{
	producer_ring_buffer_t *ring;

	size_t record_size = sizeof(dpi_session_info_t);
	size_t total_size = (size_t)size * record_size;

	if (total_size / record_size != size) {
		clib_warning("Ring buffer size calculation overflow: size=%u, record_size=%lu",
					size, record_size);
		return NULL;
	}

	if (total_size > MAX_RING_SIZE) {
		clib_warning("Ring buffer size too large: %lu bytes (max: %lu)",
					total_size, MAX_RING_SIZE);
		return NULL;
	}

	clib_warning("Allocating ring buffer: size=%u entries, record_size=%lu, total=%lu bytes",
				size, record_size, total_size);

	ring = clib_mem_alloc_aligned(sizeof(producer_ring_buffer_t), CLIB_CACHE_LINE_BYTES);
	if (!ring)
		return NULL;

	ring->session_infos = clib_mem_alloc_aligned(total_size, CLIB_CACHE_LINE_BYTES);

	if (!ring->session_infos)
	{
		clib_mem_free(ring);
		return NULL;
	}

	ring->head = 0;
	ring->tail = 0;
	ring->size = size;
	ring->mask = size - 1;

	return ring;
}

void
producer_ring_buffer_free(producer_ring_buffer_t *ring)
{
	if (!ring)
		return;

	if (ring->session_infos)
		clib_mem_free(ring->session_infos);

	clib_mem_free(ring);
}

static const char* kafka_high_perf_config[][2] = {
	{"acks", "1"},                              // Wait for leader acknowledgment only
	{"retries", "0"},                           // No retries for maximum throughput
	{"linger.ms", "5"},                         // Small linger time for batching
	{"batch.size", "1048576"},                  // 1MB batch size
	{"queue.buffering.max.kbytes", "134217728"},             // 128MB buffer
	{"compression.type", "snappy"},             // Fast compression
	{"queue.buffering.max.ms", "5"},           // Max buffering time
	{"queue.buffering.max.messages", "1000000"}, // Max messages in queue
	{"socket.send.buffer.bytes", "1048576"},    // 1MB socket buffer
	{"socket.receive.buffer.bytes", "1048576"}, // 1MB socket buffer
	{"socket.keepalive.enable", "true"},        // Keep connections alive
	{"request.timeout.ms", "5000"},             // 5 second timeout
	{"message.timeout.ms", "10000"},            // 10 second message timeout
	{"api.version.request", "true"},            // Use modern API
	{NULL, NULL}
};

clib_error_t *producer_init(const char *broker_list, const char *topic_name, u32 num_workers, u64 worker_ring_size,
		u32 ring_dequeue_threshold)
{
	kafka_producer_main_t *kpm = &kafka_producer_main;
	clib_error_t *error = 0;

	clib_memset(kpm, 0, sizeof(*kpm));

	kpm->broker_list = format(0, "%s%c", broker_list, 0);
	kpm->topic_name = format(0, "%s%c", topic_name, 0);
	kpm->enabled = 1;
	kpm->producer_worker_ring_size = max_pow2(worker_ring_size);
	kpm->ring_dequeue_threshold = ring_dequeue_threshold;
	kpm->num_workers = num_workers;

	vec_validate(kpm->udpi_producer_simple_counters, UDPI_PRODUCER_N_COUNTERS - 1);

#define _(E, n, p)                                                          \
	kpm->udpi_producer_simple_counters[UDPI_##E].name = #n;                           \
	kpm->udpi_producer_simple_counters[UDPI_##E].stat_segment_name = "/" #p "/" #n;   \
	vlib_validate_simple_counter (&kpm->udpi_producer_simple_counters[UDPI_##E], 0);  \
	vlib_zero_simple_counter (&kpm->udpi_producer_simple_counters[UDPI_##E], 0);
	foreach_udpi_producer_counter_name
#undef _

	vec_validate(kpm->worker_rings, num_workers - 1);

	for (u32 i = 0; i < num_workers; i++)
	{
		producer_worker_ring_t *ring = &kpm->worker_rings[i];

		ring->worker_id = i;
		ring->session_info_ring = producer_ring_buffer_create(kpm->producer_worker_ring_size);

		if (!ring->session_info_ring)
		{
			error = clib_error_return(0, "Failed to create ring buffer for worker %u", i);
			producer_cleanup();
			return error;
		}

		ring->records_enqueued = 0;
		ring->records_dequeued = 0;
		ring->records_dropped = 0;
	}

	return 0;
}

void producer_cleanup(void)
{
	kafka_producer_main_t *kpm = &kafka_producer_main;

	if (!kpm->enabled)
		return;

	kpm->enabled = 0;

	if (kpm->worker_rings)
	{
		for (u32 i = 0; i < kpm->num_workers; i++)
		{
			producer_worker_ring_t *ring = &kpm->worker_rings[i];
			if (ring->session_info_ring)
				producer_ring_buffer_free(ring->session_info_ring);
		}
		vec_free(kpm->worker_rings);
	}

	vec_free(kpm->broker_list);
	vec_free(kpm->topic_name);

	clib_memset(kpm, 0, sizeof(*kpm));
}

static_always_inline void assign_workers_to_producer(u32 num_workers, u32 num_producers, u32 producer_index,
		kafka_producer_thread_t *producer_thread)
{
	u32 workers_per_thread = (num_workers + num_producers - 1) / num_producers;

	u32 start_worker = producer_index * workers_per_thread;
	u32 end_worker = clib_min((producer_index + 1) * workers_per_thread, num_workers);

	if (start_worker >= num_workers)
	{
		producer_thread->num_assigned_workers = 0;
		producer_thread->assigned_workers = NULL;
		clib_warning("Producer thread %u: no workers assigned. (start=%u >= num_worker:%u)", producer_index, start_worker, num_workers);
		return;
	}

	if (end_worker <= start_worker)
	{
		producer_thread->num_assigned_workers = 0;
		producer_thread->assigned_workers = NULL;
		clib_warning("Producer thread %u: no workers assigned. (end=%u <= start:%u)", producer_index, end_worker, start_worker);
		return;
	}

	producer_thread->num_assigned_workers = end_worker - start_worker;

	if (producer_thread->num_assigned_workers > 0)
	{
		producer_thread->assigned_workers = clib_mem_alloc(sizeof(u32) * producer_thread->num_assigned_workers);
		for (u32 w = 0; w < producer_thread->num_assigned_workers; w++)
		{
			producer_thread->assigned_workers[w] = start_worker + w;
		}

		clib_warning("Producer thread %u assigned workers: %u to %u (%u workers)",
					producer_index, start_worker, end_worker - 1, producer_thread->num_assigned_workers);
	}
	else
	{
		producer_thread->assigned_workers = NULL;
		return;
	}
}

void producer_thread_fn(void *arg)
{
	dpi_main_t* dm = &dpi_main;

	vlib_worker_thread_t *w = (vlib_worker_thread_t *) arg;
	vlib_worker_thread_init (w);
	clib_mem_set_heap (w->thread_mheap);
	vlib_thread_main_t *tm = vlib_get_thread_main();

	while (!dm->kafka_enabled)
		vlib_worker_thread_barrier_check();

	kafka_producer_main_t *kpm = &kafka_producer_main;
	kafka_producer_thread_t kafka_producer_thread;
	rd_kafka_conf_t *conf;
	rd_kafka_topic_conf_t *topic_conf;
	char errstr[512];

	kafka_producer_thread.records_processed = 0;
	kafka_producer_thread.kafka_success_count = 0;
	kafka_producer_thread.kafka_error_count = 0;

	conf = rd_kafka_conf_new();
	topic_conf = rd_kafka_topic_conf_new();

	if (rd_kafka_conf_set(conf, "bootstrap.servers", (char *)kpm->broker_list,
							errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK)
	{
		clib_warning("Failed to set Kafka broker list: %s", errstr);
		rd_kafka_conf_destroy(conf);
		rd_kafka_topic_conf_destroy(topic_conf);
		producer_cleanup();
		return;
	}

	for (int j = 0; kafka_high_perf_config[j][0]; j++)
	{
		if (rd_kafka_conf_set(conf, kafka_high_perf_config[j][0],
								kafka_high_perf_config[j][1], errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK)
		{
			clib_warning("Failed to set Kafka config %s=%s: %s",
						kafka_high_perf_config[j][0], kafka_high_perf_config[j][1], errstr);
		}
	}

	kafka_producer_thread.kafka_producer = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
	if (!kafka_producer_thread.kafka_producer)
	{
		clib_warning("Failed to create Kafka producer: %s", errstr);
		rd_kafka_topic_conf_destroy(topic_conf);
		producer_cleanup();
		return;
	}

	kafka_producer_thread.kafka_topic = rd_kafka_topic_new(kafka_producer_thread.kafka_producer,
											(char *)kpm->topic_name, topic_conf);
	if (!kafka_producer_thread.kafka_topic)
	{
		clib_warning("Failed to create Kafka topic");
		producer_cleanup();
		return;
	}

	vlib_thread_registration_t *tr;
	u32 num_producer;
	u32 first_producer_index;
	uword *p = hash_get_mem (tm->thread_registrations_by_name, "producers");

	if (p == NULL)
		return;

	tr = (vlib_thread_registration_t *) p[0];

	if (tr == NULL)
	{
		clib_warning("failed to get producer thread info");
		return;
	}

	num_producer = tr->count;
	first_producer_index = tr->first_index;

	u32 producer_index = vlib_get_thread_index () - first_producer_index;

	assign_workers_to_producer(kpm->num_workers, num_producer, producer_index, &kafka_producer_thread);

	if(kafka_producer_thread.num_assigned_workers == 0)
		return;

	while(true)
	{
		vlib_worker_thread_barrier_check();

		for (u32 i = 0; i < kafka_producer_thread.num_assigned_workers; i++)
		{
			u32 worker_id = kafka_producer_thread.assigned_workers[i];
			producer_worker_ring_t *ring = &kafka_producer_main.worker_rings[worker_id];

			for (u32 i = 0; i < kafka_producer_main.ring_dequeue_threshold; i++)
			{
				u8 message[1024];
				size_t length = 0;

				if (!producer_ring_buffer_dequeue(ring, message, &length))
					break;

				if (PREDICT_FALSE(length == 0))
				{
					kafka_producer_thread.kafka_error_count++;
					kpm->counters[UDPI_EXPORTER_FAILED_RECORD_GENERATED]++;
					continue;
				}

				kafka_producer_thread.records_processed++;
				kpm->counters[UDPI_EXPORTER_SUCCESSFUL_RECORD_GENERATED]++;
				kpm->counters[UDPI_EXPORTER_SUCCESSFUL_RECORD_BYTES_GENERATED] += length;

				int result = rd_kafka_produce(kafka_producer_thread.kafka_topic,
							RD_KAFKA_PARTITION_UA,
							RD_KAFKA_MSG_F_COPY,
							message, length,
							NULL, 0,
							NULL);

				if(PREDICT_FALSE(result != 0))
				{
					kafka_producer_thread.kafka_error_count++;
					kpm->counters[UDPI_EXPORTER_FAILED_RECORD_PRODUCED]++;
					continue;
				}

				kpm->counters[UDPI_EXPORTER_SUCCESSFUL_RECORD_PRODUCED]++;
				kpm->counters[UDPI_EXPORTER_SUCCESSFUL_RECORD_BYTES_PRODUCED] += length;
				kafka_producer_thread.kafka_success_count++;
			}
		}

		#define _(INDEX, NAMEM, PREFIX)	UDPI_PRODUCER_FLUSH_COUNTER(INDEX, NAME, PREFIX)
		foreach_udpi_producer_counter_name
		#undef _
	}
}

static clib_error_t* producer_show_stats(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
	kafka_producer_main_t *kpm = &kafka_producer_main;

	if (!kpm->enabled)
	{
		return clib_error_return(0, "Kafka multi thread producer is disabled");
	}

	vlib_cli_output(vm, "=== Kafka multi thread Producer Statistics ===");
	vlib_cli_output(vm, "Configuration:");
	vlib_cli_output(vm, "  Workers: %u", kpm->num_workers);
	vlib_cli_output(vm, "  Ring size: %u entries", kpm->producer_worker_ring_size);
	vlib_cli_output(vm, "  Broker: %s", kpm->broker_list);
	vlib_cli_output(vm, "  Topic: %s", kpm->topic_name);

	vlib_cli_output(vm, "\nWorker Ring Statistics:");
	for (u32 i = 0; i < kpm->num_workers; i++)
	{
		producer_worker_ring_t *ring = &kpm->worker_rings[i];
		vlib_cli_output(vm, "  Worker %u: enqueued=%llu, dequeued:%llu, dropped=%llu",
					   i, ring->records_enqueued, ring->records_dequeued, ring->records_dropped);
	}

	return 0;
}

VLIB_CLI_COMMAND(kafka_show_stats_command, static) = {
	.path = "show producer stats",
	.short_help = "show producer statistics",
	.long_help = "Display multi thread producer statistics",
	.function = producer_show_stats,
};

VLIB_REGISTER_THREAD (producer_thread_reg, static) = {
  .name = "producers" ,
  .short_name = "prod" ,
  .function = producer_thread_fn ,
};