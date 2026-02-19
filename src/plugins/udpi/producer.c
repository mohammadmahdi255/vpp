#include <svm/fifo_types.h>

typedef struct
{
	svm_fifo_t *acquire_session_fifo;
	svm_fifo_t *release_session_fifo;
} producer_worker_t;

extern __thread producer_worker_t *producer_worker;

#ifndef CLIB_MARCH_VARIANT
__thread producer_worker_t *producer_worker;



#endif