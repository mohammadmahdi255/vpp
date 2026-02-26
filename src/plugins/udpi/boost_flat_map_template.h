#ifndef INCLUDE_UDPI_BOOST_FLAT_MAP_TEMPLATE_H_
#define INCLUDE_UDPI_BOOST_FLAT_MAP_TEMPLATE_H_

#define _FM_CONCAT_INNER(a, b)	a##b
#define _FM_CONCAT(a, b)    _FM_CONCAT_INNER(a, b)
#define _FM_TYPE(name)		_FM_CONCAT(name, _flat_map_t)
#define _FM_FN(name)		_FM_CONCAT(flat_map_, name)

#endif

#ifdef __cplusplus
#include "boost_flat_map_template.hpp"
#else

extern void _FM_FN(NAME) ();

#endif

#undef NAME
#undef KEY_TYPE
#undef VALUE_TYPE
#undef HASH_FN
#undef KEY_COMPARE_FN
#undef MAX_LOAD
#undef KEY_DTOR_FN
#undef VAL_DTOR_FN
#undef CTX_TY
#undef MALLOC_FN
#undef FREE_FN
#undef HEADER_MODE
#undef IMPLEMENTATION_MODE
#undef VT_API_FN_QUALIFIERS