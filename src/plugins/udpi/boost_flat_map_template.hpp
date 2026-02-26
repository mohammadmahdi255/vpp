#include "udpi/boost_flat_map_16_8.h"
#include <vppinfra/types.h>
#include <boost/unordered/unordered_flat_map.hpp>

#ifndef HASH_FN
#define HASH_FN boost::hash_range
#endif

#ifndef KEY_COMPARE_FN
#define KEY_COMPARE_FN std::memcmp
#endif

namespace boost {
	template<>
	struct hash<FM_TYPE(_key)> {
		std::size_t operator()(const FM_TYPE(_key)& key) const {
			return HASH_FN(key._, key._ + KEY_SIZE);
		}
	};
}

namespace std {
	template<>
	struct equal_to<FM_TYPE(_key)> {
		bool operator()(const FM_TYPE(_key)& a, const FM_TYPE(_key)& b) const {
			return KEY_COMPARE_FN(a._, b._, KEY_SIZE);
		}
	};
}

typedef boost::unordered::unordered_flat_map<FM_TYPE(_key), FM_TYPE(_value), boost::hash<FM_TYPE(_key)>, std::equal_to<FM_TYPE(_key)>> FM_TYPE();

extern "C"
{

void FM_FN(hello_world) ()
{
	printf("hello world\n");
}

FM_TYPE() * FM_FN(init) (u32 capacity)
{
	return new FM_TYPE() (capacity);
}

bool FM_FN(try_emplace) (FM_TYPE() *flat_map, FM_TYPE(_key) *key, FM_TYPE(_value) **value)
{
	assert(flat_map != nullptr && key != nullptr && value != nullptr);
	auto [it, inserted] = flat_map->try_emplace(*key);
	*value = &it->second;
	return inserted;
}

}