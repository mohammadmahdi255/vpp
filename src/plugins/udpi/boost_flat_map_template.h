#ifndef INCLUDE_UDPI_BOOST_FLAT_MAP_TEMPLATE_H_
#define INCLUDE_UDPI_BOOST_FLAT_MAP_TEMPLATE_H_

#include <stdbool.h>
#include <vppinfra/types.h>

#endif

#define _fm_fn(a, b)		boost_flat_map_##a##_##b
#define __fm_fn(a, b)		_fm_fn(a, b)
#define FM_FN(a) 			__fm_fn(NAME, a)

#define _fm_type(a, b)		boost_flat_map_##a##b##_t
#define __fm_type(a, b)		_fm_type(a, b)
#define FM_TYPE(a)			__fm_type(NAME, a)

#define _fm_struct(a, b)	struct boost_flat_map_##a##b
#define __fm_struct(a, b)	_fm_struct(a, b)
#define FM_STRUCT(a)		__fm_struct(NAME, a)

typedef FM_STRUCT(_key)
{
	u8 _[KEY_SIZE];
} FM_TYPE(_key);

typedef FM_STRUCT(_value)
{
	u8 _[VALUE_SIZE];
} FM_TYPE(_value);

#ifdef __cplusplus
#include "boost_flat_map_template.hpp"
#else

typedef FM_STRUCT() FM_TYPE();

extern void FM_FN(hello_world) ();

extern FM_TYPE() * FM_FN(init) (u32 capacity);

extern bool FM_FN(try_emplace) (FM_TYPE() *flat_map, FM_TYPE(_key) *key, FM_TYPE(_value) **value);

extern bool FM_FN(find) (FM_TYPE() *flat_map, FM_TYPE(_key) *key);

extern void FM_FN(erase) (FM_TYPE() *flat_map, FM_TYPE(_key) *key);

#endif

#undef NAME
#undef KEY_SIZE
#undef VALUE_SIZE
#undef HASH_FN
#undef KEY_COMPARE_FN