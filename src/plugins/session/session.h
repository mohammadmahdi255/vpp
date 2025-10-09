#ifndef __SESSION_H__
#define __SESSION_H__

#include <vppinfra/bihash_48_8.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

typedef struct {
  u8 data[500];   // dummy payload
  u64 index;
  u32 timer_handle;
} my_session_t;

typedef struct {
  clib_bihash_48_8_t table;
  tw_timer_wheel_2t_1w_2048sl_t timer_wheel;

  my_session_t *sessions;   // pool of sessions

  // Stats
  u64 add_count;
  u64 remove_count;

  // For rate calculation
  f64 last_check;
  u64 last_add;
  u64 last_remove;
  f64 adds_per_sec;
  f64 removes_per_sec;
} my_session_main_t;

extern my_session_main_t my_session_main;

#endif /* __MY_SESSION_H__ */
