#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include "session.h"
#include <vlib/unix/plugin.h>
#include <vpp/app/version.h>

my_session_main_t my_session_main;

// ------------------ Session logic ------------------

static void
my_session_expire (u32 session_index)
{
  my_session_main_t *sm = &my_session_main;
  my_session_t *s = pool_elt_at_index (sm->sessions, session_index);

  // TODO: if you store key->index mapping, delete from bihash here
  pool_put (sm->sessions, s);

  sm->remove_count++;
}

static void
my_session_add (vlib_main_t *vm)
{
  my_session_main_t *sm = &my_session_main;

  // Create dummy session
  my_session_t *s;
  pool_get (sm->sessions, s);
  s->index = s - sm->sessions;

  // Build dummy 48B key
  clib_bihash_kv_48_8_t kv = {0};
  for (int i = 0; i < 6; i++)
    kv.key[i] = clib_cpu_time_now () + i + s->index;

  kv.value = s->index;

  // Insert
  clib_bihash_add_del_48_8 (&sm->table, &kv, 1);

  // Add timer (fixed 5s)
  s->timer_handle = tw_timer_start_2t_1w_2048sl (
    &sm->timer_wheel, s->index, 0, 5);

  sm->add_count++;
}

static void
my_session_check_timers (vlib_main_t *vm)
{
  my_session_main_t *sm = &my_session_main;

  u32 *expired = tw_timer_expire_timers_2t_1w_2048sl (
    &sm->timer_wheel, vlib_time_now (vm));

  for (int i = 0; i < vec_len(expired); i++)
    my_session_expire (expired[i]);

  vec_free (expired);
}

// ------------------ Process Node ------------------

static uword
my_session_bench_node_fn (vlib_main_t *vm,
                          vlib_node_runtime_t *node,
                          vlib_frame_t *f)
{
  while (1) {
    // Add ~400K/s => 400 per 1ms tick
    for (int i = 0; i < 400; i++)
      my_session_add (vm);

    my_session_check_timers (vm);

    // Yield back to scheduler for 1ms
    vlib_process_suspend (vm, 1e-3);
  }
  return 0; // never reached
}


VLIB_REGISTER_NODE (my_session_bench_node) = {
  .function = my_session_bench_node_fn,
  .name = "my-session-bench",
  .type = VLIB_NODE_TYPE_PROCESS,
};

// ------------------ CLI Command ------------------

static clib_error_t *
show_my_session_stats_fn (vlib_main_t *vm,
                          unformat_input_t *input,
                          vlib_cli_command_t *cmd)
{
  my_session_main_t *sm = &my_session_main;
  f64 now = vlib_time_now (vm);

  f64 dt = now - sm->last_check;
  if (dt > 0.5) {
    sm->adds_per_sec    = (sm->add_count - sm->last_add) / dt;
    sm->removes_per_sec = (sm->remove_count - sm->last_remove) / dt;
    sm->last_check  = now;
    sm->last_add    = sm->add_count;
    sm->last_remove = sm->remove_count;
  }

  vlib_cli_output (vm, "Sessions added total: %llu", sm->add_count);
  vlib_cli_output (vm, "Sessions removed total: %llu", sm->remove_count);
  vlib_cli_output (vm, "Add rate: %.2f /s", sm->adds_per_sec);
  vlib_cli_output (vm, "Remove rate: %.2f /s", sm->removes_per_sec);

  return 0;
}

VLIB_CLI_COMMAND (show_my_session_stats_cmd, static) = {
  .path = "show my-session-stats",
  .short_help = "show my-session-stats",
  .function = show_my_session_stats_fn,
};

// ------------------ Init ------------------

static clib_error_t *
my_session_init (vlib_main_t *vm)
{
  my_session_main_t *sm = &my_session_main;

  clib_bihash_init_48_8 (&sm->table, "my-session-table", 1<<20, 1<<26);

  // Init timer wheel (callback=0, tick=1ms, max_expirations=1024)
  tw_timer_wheel_init_2t_1w_2048sl (&sm->timer_wheel,
                                    0,
                                    1e-3,
                                    1024);

  sm->sessions = 0;
  sm->add_count = sm->remove_count = 0;
  sm->last_check = vlib_time_now (vm);
  sm->last_add = sm->last_remove = 0;

  clib_warning ("my_session plugin initialized");
  return 0;
}

VLIB_INIT_FUNCTION (my_session_init);


VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "My Session Benchmark Plugin",
};