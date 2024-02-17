#ifndef UTIL_H_
#define UTIL_H_

#include <stdlib.h>

#define APPEND_TRAFFIC(D, S)                                          \
    do                                                                \
    {                                                                 \
        if (traffic_length + S > traffic_capacity)                    \
        {                                                             \
            traffic = realloc(traffic, traffic_capacity * 2);         \
            if (traffic == NULL)                                      \
            {                                                         \
                LogError("Memory reallocation for |traffic| failed"); \
                free(receive_remaining);                              \
                free(send_data);                                      \
                CLOSE_FREE_ARG_RETURN;                                \
            }                                                         \
            traffic_capacity *= 2;                                    \
        }                                                             \
        memcpy(traffic + traffic_length, D, S);                       \
        traffic_length += S;                                          \
    } while (false)

// behaves like realloc but does not copy existing data when
// expanding size to ensure best performance.
void *AdjustAlloc(void *ptr, const size_t old_size, const size_t new_size);

#endif