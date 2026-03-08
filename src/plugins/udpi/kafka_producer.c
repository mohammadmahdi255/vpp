#include <sched.h>
#include <vlib/vlib.h>
#include <vlib/threads.h>

#include <vppinfra/cpu.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/mem.h>
#include <vppinfra/vec.h>

#include <librdkafka/rdkafka.h>

#include "config.h"
#include "producer.h"

extern vlib_node_registration_t kafka_producer_node;
extern producer_thread_t *pt;

static void
dr_msg_cb(rd_kafka_t __clib_unused *rk, const rd_kafka_message_t __clib_unused *msg, void __clib_unused *opaque)
{
	if (PREDICT_FALSE(rte_ring_sp_enqueue(msg->_private, msg->payload)))
		clib_error("failed to enqueue to ring buffer");
}

static_always_inline u64
kafka_setup(producer_thread_t *pt)
{
	char errstr[512];

	const udpi_kafka_config_t *kc = &udpi_config->kafka;
	rd_kafka_conf_t *conf = rd_kafka_conf_new();
	rd_kafka_topic_conf_t *topic_conf = rd_kafka_topic_conf_new();

	for (int i = 0; i < _vec_len(kc->names); i++)
	{
		const rd_kafka_conf_res_t rv =
				rd_kafka_conf_set(conf, kc->names[i], kc->values[i], errstr, sizeof(errstr));
		if (rv != RD_KAFKA_CONF_OK)
			clib_error("kafka: config %s=%s failed: %s", kc->names[i], kc->values[i], errstr);
	}

	rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);

	pt->rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
	if (!pt->rk)
		clib_error("kafka: failed to create producer: %s", errstr);

	pt->rkt = rd_kafka_topic_new(pt->rk, kc->topic, topic_conf);
	if (!pt->rkt)
		clib_error("kafka: failed to create topic handle");

	return 0;
}

// static_always_inline u32
// produce_v4_process(producer_thread_t *pt, u32 worker_id)
// {
// 	producer_main_t *pm = &producer_main;
// 	struct rte_ring *acquire_session_v4_ring = pm->pw[worker_id].acquire_session_v4_ring;
// 	struct rte_ring *release_session_v4_ring = pm->pw[worker_id].release_session_v4_ring;
// 	void *objs[VLIB_FRAME_SIZE];
// 	rd_kafka_message_t msgs[VLIB_FRAME_SIZE];

// 	const u32 n_dequeue = rte_ring_sc_dequeue_burst(acquire_session_v4_ring, objs, VLIB_FRAME_SIZE, NULL);

// 	for (u32 i = 0; i < n_dequeue; i++)
// 	{
// 		msgs[i].partition = RD_KAFKA_PARTITION_UA;
// 		msgs[i].payload = objs[i];
// 		msgs[i].len = vec_len(objs[i]);
// 		msgs[i].key = NULL;
// 		msgs[i].key_len = 0;
// 		msgs[i]._private = release_session_v4_ring;
// 	}

// 	u32 n_vectors = rd_kafka_produce_batch(pt->rkt, RD_KAFKA_PARTITION_UA, 0, msgs, (i32) n_dequeue);
// 	rd_kafka_poll(pt->rk, 0);

// 	if (n_vectors != n_dequeue)
// 		clib_warning("leak in session pool v4 memory %u", n_dequeue - n_vectors);

// 	return n_vectors;
// }

// static_always_inline u32
// produce_v6_process(producer_thread_t *pt, u32 worker_id)
// {
// 	producer_main_t *pm   = &producer_main;
// 	struct rte_ring *acquire_session_v6_ring = pm->pw[worker_id].acquire_session_v6_ring;
// 	struct rte_ring *release_session_v6_ring = pm->pw[worker_id].release_session_v6_ring;
// 	void *objs[VLIB_FRAME_SIZE];
// 	u32 n_vectors = 0;

// 	const u32 n_dequeue = rte_ring_sc_dequeue_burst(acquire_session_v6_ring, objs, VLIB_FRAME_SIZE, NULL);

// 	for (u32 i = 0; i < n_dequeue; i++)
// 	{
// 		produce_v6_csv_record(pt->scratch, objs[i]);

// 		i32 err = rd_kafka_produce(pt->rkt,
// 									RD_KAFKA_PARTITION_UA,
// 									RD_KAFKA_MSG_F_COPY,    /* rdkafka owns msg now */
// 									pt->scratch, vec_len(pt->scratch),
// 									NULL, 0, NULL);

// 		if (PREDICT_FALSE(err))
// 		{
// 			if (rd_kafka_last_error() == RD_KAFKA_RESP_ERR__QUEUE_FULL)
// 				rd_kafka_poll(pt->rk, 0);
// 			continue;
// 		}

// 		n_vectors++;
// 	}

// 	const u32 n_enqueue = rte_ring_sp_enqueue_burst(release_session_v6_ring, objs, n_dequeue, NULL);

// 	if (n_enqueue != n_dequeue)
// 		clib_warning("leak in session pool v6 memory");

// 	return n_vectors;
// }

// void
// producer_thread_fn (void *arg)
// {
// 	vlib_worker_thread_t *wt = (vlib_worker_thread_t *) arg;
// 	u64 cpu_time_now;
// 	f64 now;
// 	u32 index = 0;

// 	vlib_worker_thread_init(wt);
// 	clib_mem_set_heap(wt->thread_mheap);
// 	vlib_main_t *vm = vlib_get_main();

// 	pt = clib_mem_alloc(sizeof(producer_thread_t));
// 	clib_memset(pt, 0, sizeof(producer_thread_t));

// 	const vlib_thread_main_t *tm = vlib_get_thread_main ();
// 	const uword *p = hash_get_mem (tm->thread_registrations_by_name, "workers");
// 	const vlib_thread_registration_t *tr = (const vlib_thread_registration_t *) p[0];
// 	const u32 n_workers = tr->count ? tr->count : 1;

// 	vec_validate(pt->scratch, 1 << 10);
// 	kafka_setup(pt);

// 	vlib_node_runtime_t *rt = vlib_node_get_runtime(vm, kafka_producer_node.index);
// 	vlib_node_runtime_sync_stats(vm, rt, 1, 0, 0);

// 	while (true)
// 	{
// 		vlib_worker_thread_barrier_check();

// 		u64 t_start = clib_cpu_time_now();

// 		u64 vectors_in_loop =
// 			produce_v4_process(pt, index) +
// 			produce_v6_process(pt, index);

// 		u64 t_end = clib_cpu_time_now();

// 		if (++index == n_workers)
// 			index = 0;

// 		/* ── node stats — show runtime table ─────────────────────── */
// 		rt = vlib_node_get_runtime(vm, kafka_producer_node.index);
// 		vlib_node_runtime_sync_stats(vm, rt, vectors_in_loop > 0, vectors_in_loop, t_end - t_start);

// 		/* ── thread line stats — loops/sec + vector rate ─────────── */
// 		vlib_increment_main_loop_counter(vm);

// 		vm->internal_node_calls += vectors_in_loop > 0;
// 		vm->internal_node_vectors += vectors_in_loop;
// 		vm->loops_this_reporting_interval++;

// 		cpu_time_now = clib_cpu_time_now();
// 		now = clib_time_now_internal(&vm->clib_time, cpu_time_now);

// 		if (PREDICT_FALSE(now >= vm->loop_interval_end))
// 		{
// 			if (vm->loop_interval_start)
// 			{
// 				f64 this_loops_per_second =
// 						((f64) vm->loops_this_reporting_interval) / (now - vm->loop_interval_start);

// 				vm->loops_per_second = vm->loops_per_second * vm->damping_constant +
// 						(1.0 - vm->damping_constant) * this_loops_per_second;

// 				if (vm->loops_per_second != 0.0)
// 					vm->seconds_per_loop = 1.0 / vm->loops_per_second;
// 				else
// 					vm->seconds_per_loop = 0.0;
// 			}

// 			vm->loop_interval_start = now;
// 			vm->loop_interval_end = now + 2e-4;
// 			vm->loops_this_reporting_interval = 0;
// 		}
// 	}
// }

// VLIB_NODE_FN (kafka_producer_node) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
// {
// 	return 0;
// }

#ifndef CLIB_MARCH_VARIANT
producer_thread_t *pt = NULL;

static clib_error_t *
producer_show_stats_fn (vlib_main_t *vm, unformat_input_t __clib_unused *input,
						 vlib_cli_command_t __clib_unused *cmd)
{
	const producer_main_t *pm = &producer_main;
	const udpi_kafka_config_t *kc = &udpi_config->kafka;

	const vlib_thread_main_t *tm = vlib_get_thread_main();
	const uword *p = hash_get_mem (tm->thread_registrations_by_name, "workers");
	const vlib_thread_registration_t *tr = (const vlib_thread_registration_t *) p[0];
	const u32 n_workers = tr->count ? tr->count : 1;

	vlib_cli_output (vm, "topic:       %s", kc->topic);

	vlib_cli_output (vm, "\nWorker rings:");
	for (u32 i = 0; i < n_workers; i++)
		vlib_cli_output (vm, "buffer ring [%u] count=%u", i, rte_ring_count(pm->pw[i].buffer_ring));

	return 0;
}

VLIB_CLI_COMMAND (producer_show_stats_cmd, static) = {
	.path = "show producer stats",
	.short_help = "show producer statistics",
	.function = producer_show_stats_fn,
};

// VLIB_REGISTER_THREAD (producer_thread_reg, static) = {
// 	.name       = "producers",
// 	.short_name = "prod",
// 	.function   = producer_thread_fn,
// };

// VLIB_REGISTER_NODE (kafka_producer_node) = {
// 	.name        = "kafka-producer",
// 	.type        = VLIB_NODE_TYPE_INTERNAL,
// 	.state       = VLIB_NODE_STATE_DISABLED,
// 	.vector_size = sizeof (u32),
// };

#endif

static clib_error_t *
kafka_producer_init(vlib_main_t __clib_unused *vm)
{
	pt = clib_mem_alloc(sizeof(producer_thread_t));
	clib_memset(pt, 0, sizeof(producer_thread_t));

	vec_validate(pt->scratch, 1 << 10);
	kafka_setup(pt);

	return 0;
}

VLIB_INIT_FUNCTION (kafka_producer_init);