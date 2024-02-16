#ifndef UTIL_H_
#define UTIL_H_

#include <stdlib.h>

// behaves like realloc but does not copy existing data when 
// expanding size to ensure best performance.
void *AdjustAlloc(void *ptr, const size_t old_size, const size_t new_size);

#endif