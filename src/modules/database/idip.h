#ifndef IDIP_H_
#define IDIP_H_

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <common/def.h>
#include <protocol/cltls/cltls_header.h>
#include <util/log.h>

typedef struct
{
    uint8_t id[ENTITY_IDENTITY_LENGTH];
    char ip[IP_STR_LENGTH];
} IdIp;

#define P
#define T IdIp
#include <set.h>

bool CreateIdIpTableFromFile(const char *file_path, set_IdIp *table_ret);
void FreeIdIpTable(set_IdIp *table);

#endif