#include "util.h"

void *AdjustAlloc(void *ptr, const size_t old_size, const size_t new_size)
{
    if (old_size > new_size)
    {
        return realloc(ptr, new_size);
    }
    else if (old_size < new_size)
    {
        free(ptr);
        return malloc(new_size);
    }
    else
    {
        return ptr;
    }
}