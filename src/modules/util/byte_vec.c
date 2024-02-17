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

bool ByteVecAppendFromByteVec(ByteVec *dest_byte_vec, const ByteVec *src_byte_vec)
{
    return ByteVecAppendBlock(dest_byte_vec, src_byte_vec->data, src_byte_vec->size);
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

bool ByteVecCopyFromByteVec(ByteVec *dest_byte_vec,
                            const size_t pos,
                            const ByteVec *src_byte_vec)
{
    return ByteVecCopyBlock(dest_byte_vec, pos, src_byte_vec->data, src_byte_vec->size);
}

void ByteVecClear(ByteVec *byte_vec)
{
    byte_vec->size = 0;
}

bool ByteVecResize(ByteVec *byte_vec, const size_t new_size)
{
    if (new_size == byte_vec->size)
    {
        return true;
    }
    if (new_size < byte_vec->size)
    {
        byte_vec->size = new_size;
        return true;
    }
    else
    {
        if (!ByteVecEnsureCapacity(byte_vec, new_size))
        {
            return false;
        }

        byte_vec->size = new_size;
        return true;
    }
}

void ByteVecFree(ByteVec *byte_vec)
{
    if (byte_vec->data != NULL)
    {
        free(byte_vec->data);
    }
}