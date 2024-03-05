#ifndef MQTT_COMMON_H_
#define MQTT_COMMON_H_

#include <stdio.h>
#include <stdint.h>

#define MAX_FULL_PRINT_LENGTH 1024
#define HEAD_TAIL_PRINT_LENGTH 16
#define MAX_SOCKET_BLOCK_SIZE (4 * 1024 * 1024)

void PrintBytes(const uint8_t *data, const size_t length);
void PrintHeadTailBytes(const uint8_t *data,
                        const size_t length,
                        const size_t print_count);

#endif