#include <vlib/vlib.h>

#include <vnet/vnet.h>

#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include "detunnel.h"

#define foreach_failed_detunnel_next				\
	_(drop_next, DROP, "drop")

enum
{
#define _(var, id, name) FAILED_NEXT_##id,
	foreach_failed_detunnel_next
#undef _
	FAILED_NEXT_N,
};

typedef struct
{
	u32 counter_if_index;
	vlib_simple_counter_main_t counter;
} failed_detunnel_main_t;

typedef struct
{
	counter_t counters[MAX_IF_SIZE];
} failed_detunnel_worker_t;

extern __thread failed_detunnel_worker_t failed_detunnel_worker;
extern failed_detunnel_main_t failed_detunnel_main;
extern vlib_node_registration_t failed_detunnel;

static_always_inline void
add_trace(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b)
{
	if (b->flags & VLIB_BUFFER_IS_TRACED)
		vlib_add_trace(vm, node, b, 0);
}

static_always_inline void
process_buffer_1x(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next, u8 is_trace)
{
	failed_detunnel_worker_t *fdw = &failed_detunnel_worker;
	const u32 sw_idx = vnet_buffer(b)->sw_if_index[VLIB_RX];

	next[0] = FAILED_NEXT_DROP;
	fdw->counters[sw_idx]++;

	if (is_trace)
		add_trace(vm, node, b);
}

static_always_inline u64
failed_detunnel_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_trace)
{
	vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
	u16 nexts[VLIB_FRAME_SIZE];
	vlib_buffer_t **b = bufs;
	u16 *next = nexts;

	u32 *from = vlib_frame_vector_args(frame);
	u32 n_left_from = frame->n_vectors;

	vlib_get_buffers(vm, from, bufs, n_left_from);

	while (n_left_from >= 4)
	{

		if (n_left_from >= 8)
		{
			vlib_prefetch_buffer_header(b[4], LOAD);
			vlib_prefetch_buffer_header(b[5], LOAD);
			vlib_prefetch_buffer_header(b[6], LOAD);
			vlib_prefetch_buffer_header(b[7], LOAD);

			vlib_prefetch_buffer_data(b[4], LOAD);
			vlib_prefetch_buffer_data(b[5], LOAD);
			vlib_prefetch_buffer_data(b[6], LOAD);
			vlib_prefetch_buffer_data(b[7], LOAD);
		}

		process_buffer_1x(vm, node, b[0], &next[0], is_trace);
		process_buffer_1x(vm, node, b[1], &next[1], is_trace);
		process_buffer_1x(vm, node, b[2], &next[2], is_trace);
		process_buffer_1x(vm, node, b[3], &next[3], is_trace);

		b += 4;
		next += 4;
		n_left_from -= 4;
	}

	while (n_left_from > 0)
	{
		process_buffer_1x(vm, node, b[0], next, is_trace);

		b++;
		next++;
		n_left_from--;
	}

	failed_detunnel_main_t *fdm = &failed_detunnel_main;
	failed_detunnel_worker_t *fdw = &failed_detunnel_worker;

	for (u32 sw_idx = 0; sw_idx <= fdm->counter_if_index; sw_idx++)
	{
		vlib_increment_simple_counter(&fdm->counter, vm->thread_index,
				sw_idx, fdw->counters[sw_idx]);

		fdw->counters[sw_idx] = 0;
	}

	vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

	return frame->n_vectors;
}

VLIB_NODE_FN (failed_detunnel) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
	return failed_detunnel_inline(vm, node, frame, node->flags & VLIB_NODE_FLAG_TRACE);
}

#ifndef CLIB_MARCH_VARIANT
__thread failed_detunnel_worker_t failed_detunnel_worker;
failed_detunnel_main_t failed_detunnel_main;

static u8 *format_failed_detunnel_trace(u8 *s, va_list *args)
{
	vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
	vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
	return format(s, "failed to detunnel");
}

VLIB_REGISTER_NODE (failed_detunnel) = {
	.name = "failed-detunnel",
	.vector_size = sizeof(u32),
	.format_trace = format_failed_detunnel_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_next_nodes = FAILED_NEXT_N,
	.next_nodes = {
#define _(var, id, name) [FAILED_NEXT_##id] = (name),
	foreach_failed_detunnel_next
#undef _
	},
};

void failed_detunnel_counter_validate(u32 sw_if_index)
{
	failed_detunnel_main_t *fdm = &failed_detunnel_main;

	clib_warning("interface max index %u", sw_if_index);

	if (PREDICT_FALSE(fdm->counter_if_index < sw_if_index))
	{
		vlib_validate_simple_counter(&fdm->counter, sw_if_index);

		for (u32 i = fdm->counter_if_index + 1; i <= sw_if_index; i++)
		{
			vlib_zero_simple_counter(&fdm->counter, fdm->counter_if_index);
		}

		fdm->counter_if_index = sw_if_index;
	}
}

#endif

static clib_error_t *
failed_detunnel_worker_init(vlib_main_t __clib_unused *vm)
{
	failed_detunnel_worker_t *fdw = &failed_detunnel_worker;
	clib_memset(fdw->counters, 0, sizeof(fdw->counters));
	return 0;
}

static clib_error_t *
failed_detunnel_init(vlib_main_t __clib_unused *vm)
{
	failed_detunnel_main_t *fdm = &failed_detunnel_main;
	vnet_main_t *vnm = vnet_get_main();
	vnet_interface_main_t *im = &vnm->interface_main;
	fdm->counter_if_index = pool_elts(im->sw_interfaces);

	vlib_simple_counter_main_t *sc = &fdm->counter;
	sc->name = "failed_packets";
	sc->stat_segment_name = "/detunnel/failed/";
	vlib_validate_simple_counter(sc, fdm->counter_if_index);
	vlib_zero_simple_counter(sc, fdm->counter_if_index);

	return 0;
}

VLIB_WORKER_INIT_FUNCTION (failed_detunnel_worker_init);
VLIB_INIT_FUNCTION (failed_detunnel_init);
