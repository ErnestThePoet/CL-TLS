#ifndef UTIL_H_
#define UTIL_H_

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

bool Hex2Bin(const char *hex, uint8_t *bin,const size_t bin_size);
void Bin2Hex(const uint8_t *bin, char *hex, const size_t bin_size);

#endif