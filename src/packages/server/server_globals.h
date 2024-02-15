#ifndef SERVER_GLOBALS_H_
#define SERVER_GLOBALS_H_

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#include <pthread.h>

#include <database/idip.h>
#include <database/permitted_ids.h>
#include <common/log.h>

typedef struct
{
    uint8_t cipher_suite;
} CipherSuite;
#define P
#define T CipherSuite
#include <set.h>

uint8_t kServerIdentity[CLTLS_IDENTITY_LENGTH] = {0};

set_CipherSuite kServerCipherSuiteSet;
set_IdIp kServerIdIpTable;
set_Id kServerPermittedIdSet;

char kServerIdIpDatabasePath[60] = {0};
char kServerPermittedIdsDatabasePath[60] = {0};

pthread_mutex_t kServerPermittedIdsMutex;

bool InitializeGlobals(const char *config_file_path);
void FreeGlobals();

#endif