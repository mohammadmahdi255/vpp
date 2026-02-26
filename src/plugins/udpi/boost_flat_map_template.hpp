#include <boost/unordered/unordered_flat_map.hpp>

#ifndef HASH_FN
#  define HASH_FN boost::hash<KEY_TYPE>
#endif

#ifndef KEY_COMPARE_FN
#  define KEY_COMPARE_FN std::equal_to<KEY_TYPE>
#endif

typedef boost::unordered::unordered_flat_map<KEY_TYPE, VALUE_TYPE, HASH_FN, KEY_COMPARE_FN> _FM_TYPE(NAME);

extern "C"
{

void _FM_FN(NAME) ()
{
	printf("hello world\n");
}

}