#include "vat/vat.h"
#include <boost/unordered/unordered_flat_map.hpp>


typedef boost::unordered::unordered_flat_map<KEY_TYPE, VALUE_TYPE, HASH_FN, KEY_COMPARE_FN> _FM_TYPE(NAME);

extern "C"
{

void _FM_FN(NAME) ()
{
    printf("hello world\n");
}

}