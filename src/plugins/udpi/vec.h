#ifndef UDPI_VEC_H_
#define UDPI_VEC_H_

#include <vlib/vlib.h>

static_always_inline void
_vec_fast_delete(void *v, u64 n_del, u64 first, u64 elt_sz)
{
  u64 n_bytes_del, n_bytes_to_move, len = vec_len (v);
  u8 *dst;

  if (n_del == 0)
    return;

  ASSERT(first + n_del <= len);

  n_bytes_del = n_del * elt_sz;
  n_bytes_to_move = (len - first - n_del) * elt_sz;
  dst = v + first * elt_sz;

  if (n_bytes_to_move > 0)
    clib_memmove(dst, dst + n_bytes_del, n_bytes_to_move);

  _vec_set_len(v, _vec_len (v) - n_del, elt_sz);
}

#define vec_fast_delete(V, N, M) _vec_fast_delete((void *) (V), N, M, _vec_elt_sz(V))

#endif