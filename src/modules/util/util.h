#ifndef UTIL_H_
#define UTIL_H_

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <common/def.h>

bool IdentityHex2Bin(const char *identity_hex, uint8_t *identity_bin);
void IdentityBin2Hex(const uint8_t *identity_bin, char *identity_hex);

#endif