#include "byte_vec.h"

bool ByteVecInit(ByteVec *byte_vec_ret)
{
    return ByteVecInitWithCapacity(byte_vec_ret, 10);
}

bool ByteVecInitWithCapacity(ByteVec *byte_vec_ret, const size_t initial_capacity)
{
    uint8_t *data = malloc(initial_capacity);
    if (data == NULL)
    {
        return false;
    }

    byte_vec_ret->size = 0;
    byte_vec_ret->capacity = initial_capacity;
    byte_vec_ret->data = data;

    return true;
}

bool ByteVecEnsureCapacity(ByteVec *byte_vec, const size_t capacity)
{
    if (byte_vec->data == NULL || byte_vec->capacity == 0)
    {
        return false;
    }

    if (byte_vec->capacity >= capacity)
    {
        return true;
    }

    size_t new_capacity = byte_vec->capacity;
    while (new_capacity < capacity)
    {
        new_capacity *= 2;
    }

    uint8_t *data = realloc(byte_vec->data, new_capacity);
    if (data == NULL)
    {
        return false;
    }

    byte_vec->capacity = new_capacity;
    byte_vec->data = data;

    return true;
}

bool ByteVecAppendBlock(ByteVec *byte_vec, const uint8_t *src, const size_t count)
{
    return ByteVecCopyBlock(byte_vec, byte_vec->size, src, count);
}

bool ByteVecCopyBlock(ByteVec *byte_vec,
                      const size_t pos,
                      const uint8_t *src,
                      const size_t count)
{
    if (!ByteVecEnsureCapacity(byte_vec, pos + count))
    {
        return false;
    }

    memcpy(byte_vec->data + pos, src, count);

    return true;
}

// Clear() sets size to 0 without freeing data.
void Clear(ByteVec *byte_vec)
{
    byte_vec->size = 0;
}

// ShrinkSize() sets size to a smaller one without freeing data.
void ShrinkSize(ByteVec *byte_vec, const size_t new_size)
{
    if (new_size < byte_vec->size)
    {
        byte_vec->size = new_size;
    }
}

void ByteVecFree(ByteVec *byte_vec)
{
    if (byte_vec->data != NULL)
    {
        free(byte_vec->data);
    }
}