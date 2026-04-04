#define _SIMD_LANES_512_u8    64
#define _SIMD_LANES_512_u16   32
#define _SIMD_LANES_512_u32   16
#define _SIMD_LANES_512_u64    8

#define _SIMD_LANES_256_u8    32
#define _SIMD_LANES_256_u16   16
#define _SIMD_LANES_256_u32    8
#define _SIMD_LANES_256_u64    4

#define _SIMD_LANES_128_u8    16
#define _SIMD_LANES_128_u16    8
#define _SIMD_LANES_128_u32    4
#define _SIMD_LANES_128_u64    2

#if defined(CLIB_HAVE_VEC512)
  #define _SIMD_VBITS 512
#elif defined(CLIB_HAVE_VEC256)
  #define _SIMD_VBITS 256
#else
  #define _SIMD_VBITS 128
#endif

#define __SC2(a, b)					a##b
#define __SC3(a, b, c)				a##b##c
#define _SC2(a, b)					__SC2(a, b)
#define _SC3(a, b, c)				__SC3(a, b, c)
#define _SIMD_GET_LANES(bits, t)	_SC2(_SC2(_SC2(_SIMD_LANES_, bits), _), t)
#define _SIMD_LANES(t)				_SIMD_GET_LANES(_SIMD_VBITS, t)

#define __simd_u16_t(t)					_SC3(t, x, _SIMD_LANES(t))
#define __simd_u16(t, n)				_SC3(n, _, __simd_u16_t(t))
#define __simd_u16_size(t)					_SIMD_LANES(t)
#define __simd_u16_splat(t, v)				_SC3(t, x, _SC2(_SIMD_LANES(t), _splat))(v)
#define __simd_u16_load_unaligned(t, p)		_SC3(t, x, _SC2(_SIMD_LANES(t), _load_unaligned))(p)
#define __simd_u16_store_unaligned(t, p, v)	_SC3(t, x, _SC2(_SIMD_LANES(t), _store_unaligned))(p, v)

/* u8 */
#define simd_u8_t                   __simd_u16_t(u8)
#define simd_u8(n)                  __simd_u16(u8, n)
#define simd_u8_size              	__simd_u16_size(u8)
#define simd_u8_splat(v)            __simd_u16_splat(u8, v)
#define simd_u8_load(p)             __simd_u16_load_unaligned(u8, p)
#define simd_u8_store(p, v)         __simd_u16_store_unaligned(u8, p, v)

/* u16 */
#define simd_u16_t                  __simd_u16_t(u16)
#define simd_u16(n)                 __simd_u16(u16, n)
#define simd_u16_size             	__simd_u16_size(u16)
#define simd_u16_splat(v)           __simd_u16_splat(u16, v)
#define simd_u16_load(p)            __simd_u16_load_unaligned(u16, p)
#define simd_u16_store(p, v)        __simd_u16_store_unaligned(u16, p, v)

/* u32 */
#define simd_u32_t                  __simd_u16_t(u32)
#define simd_u32(n)                 __simd_u16(u32, n)
#define simd_u32_size             	__simd_u16_size(u32)
#define simd_u32_splat(v)           __simd_u16_splat(u32, v)
#define simd_u32_load(p)            __simd_u16_load_unaligned(u32, p)
#define simd_u32_store(p, v)        __simd_u16_store_unaligned(u32, p, v)

/* u64 */
#define simd_u64_t                  __simd_u16_t(u64)
#define simd_u64(n)                 __simd_u16(u64, n)
#define simd_u64_size             	__simd_u16_size(u64)
#define simd_u64_splat(v)           __simd_u16_splat(u64, v)
#define simd_u64_load(p)            __simd_u16_load_unaligned(u64, p)
#define simd_u64_store(p, v)        __simd_u16_store_unaligned(u64, p, v)