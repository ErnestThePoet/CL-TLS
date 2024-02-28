#ifndef BYTE_VEC_H_
#define BYTE_VEC_H_

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

typedef struct
{
    size_t capacity;
    size_t size;
    uint8_t *data;
} ByteVec;

// byte_vec_ret must point to an allocated space
void ByteVecInit(ByteVec *byte_vec_ret);

// byte_vec_ret must point to an allocated space
void ByteVecInitWithCapacity(ByteVec *byte_vec_ret, const size_t initial_capacity);

void ByteVecEnsureCapacity(ByteVec *byte_vec, const size_t capacity);

void ByteVecPushBack(ByteVec *byte_vec, const uint8_t value);
void ByteVecPushBackBlock(ByteVec *byte_vec, const uint8_t *src, const size_t count);
void ByteVecPushBackBlockFromByteVec(ByteVec *dest_byte_vec, const ByteVec *src_byte_vec);

// ByteVecClear() sets size to 0 without freeing extra capacity.
void ByteVecClear(ByteVec *byte_vec);
// if new_size for ByteVecResize() is smaller, extra capacity is not freed.
void ByteVecResize(ByteVec *byte_vec, const size_t new_size);
// if diff for ByteVecResizeBy() is negative, extra capacity is not freed.
void ByteVecResizeBy(ByteVec *byte_vec, const ssize_t diff);

void ByteVecFree(ByteVec *byte_vec);

#endif