#ifndef PERMITTED_IDS_H_
#define PERMITTED_IDS_H_

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <protocol/cltls/cltls_header.h>
#include <common/log.h>

typedef struct
{
    uint8_t id[CLTLS_IDENTITY_LENGTH];
} Id;
#define P
#define T Id
#include <set.h>

bool CreatePermittedIdSetFromFile(const char *file_path, set_Id *set_ret);
void FreePermittedIdSet(set_Id *set_);

#endif