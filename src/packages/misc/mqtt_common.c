#include "mqtt_common.h"

void PrintBytes(const uint8_t *data, const size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        printf("%02hhX ", data[i]);
    }
    putchar('\n');
}

void PrintHeadTailBytes(const uint8_t *data,
                        const size_t length,
                        const size_t print_count)
{
    printf("First %zu bytes:\n", print_count);
    for (size_t i = 0; i < print_count; i++)
    {
        printf("%02hhX ", data[i]);
    }
    putchar('\n');

    printf("Last %zu bytes:\n", print_count);
    for (size_t i = 0; i < print_count; i++)
    {
        printf("%02hhX ", data[length - print_count + i]);
    }
    putchar('\n');
}