#include "byte_vec.h"

void ByteVecInit(ByteVec *byte_vec_ret)
{
    ByteVecInitWithCapacity(byte_vec_ret, 10);
}

void ByteVecInitWithCapacity(ByteVec *byte_vec_ret, const size_t initial_capacity)
{
    uint8_t *data = malloc(initial_capacity);
    if (data == NULL)
    {
        LogError("Failed to allocate memory in ByteVecInitWithCapacity()");
        exit(EXIT_FAILURE);
    }

    byte_vec_ret->size = 0;
    byte_vec_ret->capacity = initial_capacity;
    byte_vec_ret->data = data;
}

void ByteVecEnsureCapacity(ByteVec *byte_vec, const size_t capacity)
{
    if (byte_vec->data == NULL || byte_vec->capacity == 0)
    {
        LogWarn("Calling ByteVecEnsureCapacity() with an uninitialized byte_vec");
        return;
    }

    if (byte_vec->capacity >= capacity)
    {
        return;
    }

    size_t new_capacity = byte_vec->capacity;
    while (new_capacity < capacity)
    {
        new_capacity *= 2;
    }

    uint8_t *data = realloc(byte_vec->data, new_capacity);
    if (data == NULL)
    {
        LogError("Failed to allocate memory in ByteVecEnsureCapacity()");
        exit(EXIT_FAILURE);
    }

    byte_vec->capacity = new_capacity;
    byte_vec->data = data;
}

void ByteVecPushBack(ByteVec *byte_vec, const uint8_t value)
{
    ByteVecResizeBy(byte_vec, 1);
    byte_vec->data[byte_vec->size - 1] = value;
}

void ByteVecPushBackBlock(ByteVec *byte_vec, const uint8_t *src, const size_t count)
{
    const size_t previous_size = byte_vec->size;
    ByteVecResizeBy(byte_vec, count);
    memcpy(byte_vec->data + previous_size, src, count);
}

void ByteVecPushBackBlockFromByteVec(ByteVec *dest_byte_vec, const ByteVec *src_byte_vec)
{
    ByteVecPushBackBlock(dest_byte_vec, src_byte_vec->data, src_byte_vec->size);
}

void ByteVecClear(ByteVec *byte_vec)
{
    byte_vec->size = 0;
}

void ByteVecResize(ByteVec *byte_vec, const size_t new_size)
{
    if (new_size <= byte_vec->size)
    {
        byte_vec->size = new_size;
    }
    else
    {
        ByteVecEnsureCapacity(byte_vec, new_size);
        byte_vec->size = new_size;
    }
}

void ByteVecResizeBy(ByteVec *byte_vec, const ssize_t diff)
{
    if (diff < 0 && -diff > byte_vec->size)
    {
        ByteVecResize(byte_vec, 0);
    }
    else
    {
        ByteVecResize(byte_vec, byte_vec->size + diff);
    }
}

void ByteVecFree(ByteVec *byte_vec)
{
    if (byte_vec->data != NULL)
    {
        free(byte_vec->data);
    }
}