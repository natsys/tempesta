#include <stdlib.h>
#include "../../pool.h"

void *
tfw_pool_alloc(TfwPool * p, size_t n)
{
	return malloc(n);
}

void
tfw_pool_free(TfwPool * p, void *ptr, size_t n)
{
	free(ptr);
}

TfwPool *
__tfw_pool_new(size_t n)
{
	return NULL;
}

void
tfw_pool_destroy(TfwPool * p)
{
}
