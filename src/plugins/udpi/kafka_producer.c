#include <vlib/vlib.h>
#include <vlib/threads.h>

#include <vppinfra/cpu.h>
#include <vppinfra/format.h>
#include <vppinfra/mem.h>
#include <vppinfra/vec.h>

#include <librdkafka/rdkafka.h>

#include "config.h"
#include "metadata_generator.h"
#include "producer.h"

/* ── Constants ───────────────────────────────────────────────────── */

#define PRODUCER_POLL_INTERVAL_NS   1000000 /* 1ms between loops            */

typedef struct
{
	rd_kafka_t *rk;
	rd_kafka_topic_t *rkt;

	u8 *scratch;

	/* stats */
	u64   records_produced;
	u64   records_dropped;
	u64   kafka_errors;

	CLIB_CACHE_LINE_ALIGN_MARK (pad);
} producer_thread_t;

typedef struct
{
	/* one ring per vpp worker — allocated at init */
	struct rte_ring **worker_rings;     /* [n_workers] */

	/* kafka state */
	u8   kafka_ready;                   /* atomic — set by producer threads */

	/* config */
	u32  n_workers;
	u32  n_producers;
	u32  ring_size;

} kafka_producer_main_t;

static kafka_producer_main_t kafka_producer_main;

/* ── Kafka setup ─────────────────────────────────────────────────── */

static const char *kafka_perf_config[][2] = {
	{ "acks",                           "1"         },
	{ "retries",                        "0"         },
	{ "linger.ms",                      "5"         },
	{ "batch.size",                     "1048576"   },
	{ "queue.buffering.max.kbytes",     "131072"    },
	{ "compression.type",               "snappy"    },
	{ "queue.buffering.max.ms",         "5"         },
	{ "queue.buffering.max.messages",   "1000000"   },
	{ "socket.keepalive.enable",        "true"      },
	{ "request.timeout.ms",             "5000"      },
	{ "message.timeout.ms",             "10000"     },
	{ "api.version.request",            "true"      },
	{ NULL, NULL }
};

static u64
kafka_setup(producer_thread_t *pt)
{
	char errstr[512];

	const udpi_kafka_config_t *kc = &udpi_config->producer.kafka;
	rd_kafka_conf_t *conf = rd_kafka_conf_new();

	const rd_kafka_conf_res_t rv =
			rd_kafka_conf_set(conf, "bootstrap.servers", kc->brokers, errstr, sizeof (errstr));

	/* broker */
	if (rv != RD_KAFKA_CONF_OK)
		clib_error("kafka: failed to set brokers: %s", errstr);

	/* performance tuning */
	for (int i = 0; kafka_perf_config[i][0]; i++)
	{
		const rd_kafka_conf_res_t rv =
				rd_kafka_conf_set(conf, kafka_perf_config[i][0], kafka_perf_config[i][1], errstr, sizeof(errstr));
		if (rv != RD_KAFKA_CONF_OK)
			clib_error("kafka: config %s=%s failed: %s", kafka_perf_config[i][0], kafka_perf_config[i][1], errstr);
	}

	pt->rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
	if (!pt->rk)
		clib_error("kafka: failed to create producer: %s", errstr);

	pt->rkt = rd_kafka_topic_new(pt->rk, kc->topic, NULL);
	if (!pt->rkt)
		clib_error("kafka: failed to create topic handle");

	return 0;
}

/* ── Produce burst — non-blocking, returns vectors produced ──────── */

static_always_inline u32
produce_burst(producer_thread_t *pt, u32 worker_id)
{
	producer_main_t *pm   = &producer_main;
	struct rte_ring *ring = pm->pw[worker_id].acquire_session_v4_ring;
	void *objs[VLIB_FRAME_SIZE];
	u32 n_vectors = 0;

	u32 n = rte_ring_sc_dequeue_burst(ring, (void **) objs, VLIB_FRAME_SIZE, NULL);

	for (u32 i = 0; i < n; i++)
	{
		produce_v4_csv_record(pt->scratch, objs[i]);

		clib_warning ("%v", pt->scratch);

		i32 err = rd_kafka_produce(pt->rkt,
									RD_KAFKA_PARTITION_UA,
									RD_KAFKA_MSG_F_COPY,    /* rdkafka owns msg now */
									pt->scratch, vec_len(pt->scratch),
									NULL, 0, NULL);

		if (PREDICT_FALSE(err))
		{
			if (rd_kafka_last_error() == RD_KAFKA_RESP_ERR__QUEUE_FULL)
				rd_kafka_poll(pt->rk, 0);

			pt->kafka_errors++;
			continue;
		}

		pt->records_produced++;
		n_vectors++;
	}

	return n_vectors;
}

void
producer_thread_fn (void *arg)
{
	// kafka_producer_main_t *pm = &kafka_producer_main;
	vlib_worker_thread_t *w  = (vlib_worker_thread_t *) arg;
	vlib_thread_main_t   *tm = vlib_get_thread_main();
	vlib_main_t *vm = vlib_get_main();
	u64 cpu_time_now;
 	f64 now;

	vlib_worker_thread_init(w);
	clib_mem_set_heap(w->thread_mheap);

	producer_thread_t *pt = clib_mem_alloc_aligned(sizeof(*pt), CLIB_CACHE_LINE_BYTES);
	clib_memset(pt, 0, sizeof(*pt));

	vec_validate(pt->scratch, 1 << 10);

	u64 *p = hash_get_mem(tm->thread_registrations_by_name, "workers");
	vlib_thread_registration_t *tr = (vlib_thread_registration_t *) p[0];

	kafka_setup(pt);

	while (true)
	{
		vlib_worker_thread_barrier_check();

		u64 vectors_in_loop = 0;

		if (tr->count == 0)
		{
			vectors_in_loop += produce_burst(pt, 0);
		}
		else
		{
			for (u32 i = 0; i < tr->count; i++)
				vectors_in_loop += produce_burst(pt, i);
		}

		rd_kafka_poll (pt->rk, 0);

		vlib_increment_main_loop_counter (vm);

		vm->internal_node_vectors += vectors_in_loop;
		vm->internal_node_calls++;
		vm->loops_this_reporting_interval++;

		cpu_time_now = clib_cpu_time_now();
		now = clib_time_now_internal(&vm->clib_time, cpu_time_now);

		if (PREDICT_FALSE(now >= vm->loop_interval_end))
		{
			if (vm->loop_interval_start)
			{
				f64 this_loops_per_second =
						((f64) vm->loops_this_reporting_interval) / (now - vm->loop_interval_start);

				vm->loops_per_second = vm->loops_per_second * vm->damping_constant +
						(1.0 - vm->damping_constant) * this_loops_per_second;

				if (vm->loops_per_second != 0.0)
					vm->seconds_per_loop = 1.0 / vm->loops_per_second;
				else
					vm->seconds_per_loop = 0.0;
			}

			vm->loop_interval_start = now;
			vm->loop_interval_end = now + 2e-4;
			vm->loops_this_reporting_interval = 0;
		}

		if (vectors_in_loop == 0)
			CLIB_PAUSE ();
	}
}

static clib_error_t *
kafka_producer_init(vlib_main_t *vm)
{
	kafka_producer_main_t            *pm = &kafka_producer_main;
	const udpi_producer_config_t  *pc = &udpi_config->producer;
	// const udpi_kafka_config_t  *kc = &udpi_config->producer.kafka;
	vlib_thread_main_t         *tm = vlib_get_thread_main();

	clib_memset (pm, 0, sizeof (*pm));

	pm->ring_size = max_pow2 (pc->ring_capacity);

	/* count vpp workers */
	uword *p = hash_get_mem (tm->thread_registrations_by_name, "workers");
	vlib_thread_registration_t *tr = p ? (vlib_thread_registration_t *) p[0] : NULL;
	pm->n_workers = tr ? tr->count : 1;

	/* allocate one ring per vpp worker */
	// pm->worker_rings = clib_mem_alloc (sizeof (struct rte_ring *) * pm->n_workers);

	// for (u32 i = 0; i < pm->n_workers; i++)
	// {
	// 	char name[64];
	// 	snprintf (name, sizeof (name), "producer-worker-%u", i);
	// 	pm->worker_rings[i] = rte_ring_create (name, pm->ring_size,
	// 											SOCKET_ID_ANY,
	// 											RING_F_SP_ENQ | RING_F_SC_DEQ);
	// 	if (!pm->worker_rings[i])
	// 		return clib_error_return (0, "failed to create ring for worker %u", i);
	// }

	return 0;
}

VLIB_INIT_FUNCTION (kafka_producer_init);

/* ── CLI ─────────────────────────────────────────────────────────── */

static clib_error_t *
producer_show_stats_fn (vlib_main_t *vm, unformat_input_t __clib_unused *input,
						 vlib_cli_command_t __clib_unused *cmd)
{
	// producer_main_t *pm = &producer_main;

	// vlib_cli_output (vm, "kafka ready: %s",
	// 				 pm->kafka_ready ? "yes" : "no (connecting...)");
	// vlib_cli_output (vm, "broker:      %s", pm->broker);
	// vlib_cli_output (vm, "topic:       %s", pm->topic);
	// vlib_cli_output (vm, "workers:     %u", pm->n_workers);
	// vlib_cli_output (vm, "ring size:   %u", pm->ring_size);

	// vlib_cli_output (vm, "\nWorker rings:");
	// for (u32 i = 0; i < pm->n_workers; i++)
	// 	vlib_cli_output (vm, "  [%u] count=%u", i,
	// 					 rte_ring_count (pm->worker_rings[i]));

	// vlib_cli_output (vm, "\nCounters:");
	// vlib_cli_output (vm, "  produced: %llu", pm->counters[UDPI_PRODUCER_COUNTER_PRODUCED]);
	// vlib_cli_output (vm, "  dropped:  %llu", pm->counters[UDPI_PRODUCER_COUNTER_DROPPED]);
	// vlib_cli_output (vm, "  errors:   %llu", pm->counters[UDPI_PRODUCER_COUNTER_KAFKA_ERROR]);

	return 0;
}

VLIB_CLI_COMMAND (producer_show_stats_cmd, static) = {
	.path       = "show producer stats",
	.short_help = "show producer statistics",
	.function   = producer_show_stats_fn,
};

VLIB_REGISTER_THREAD (producer_thread_reg, static) = {
	.name       = "producers",
	.short_name = "prod",
	.function   = producer_thread_fn,
};