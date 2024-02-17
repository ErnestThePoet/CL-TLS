#ifndef BYTE_VEC_H_
#define BYTE_VEC_H_

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
    size_t capacity;
    size_t size;
    uint8_t *data;
} ByteVec;

// byte_vec_ret must point to an allocated space
bool ByteVecInit(ByteVec *byte_vec_ret);

// byte_vec_ret must point to an allocated space
bool ByteVecInitWithCapacity(ByteVec *byte_vec_ret, const size_t initial_capacity);

bool ByteVecEnsureCapacity(ByteVec *byte_vec, const size_t capacity);

bool ByteVecAppendBlock(ByteVec *byte_vec, const uint8_t *src, const size_t count);
bool ByteVecCopyBlock(ByteVec *byte_vec, const size_t pos, const uint8_t *src, const size_t count);

// Clear() sets size to 0 without freeing data.
void Clear(ByteVec *byte_vec);
// ShrinkSize() sets size to a smaller one without freeing data.
void ShrinkSize(ByteVec *byte_vec, const size_t new_size);

void ByteVecFree(ByteVec *byte_vec);

#endif