#ifndef SERVER_GLOBALS_H_
#define SERVER_GLOBALS_H_

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#include <pthread.h>

#include <common/def.h>
#include <util/log.h>

#include <database/idip.h>
#include <database/permitted_ids.h>

typedef struct
{
    uint8_t cipher_suite;
} CipherSuite;
#define P
#define T CipherSuite
#include <set.h>

uint8_t kServerIdentity[CLTLS_IDENTITY_LENGTH] = {0};
uint8_t kKgcPublicKey[CLTLS_ENTITY_PUBLIC_KEY_LENGTH] = {0};
uint8_t kServerPublicKey[CLTLS_ENTITY_FULL_PUBLIC_KEY_LENGTH] = {0};
uint8_t kServerPrivateKey[CLTLS_ENTITY_PRIVATE_KEY_LENGTH] = {0};

set_CipherSuite kServerCipherSuiteSet;
// ID/IP table is manually maintained in a file which is loaded
// at startup
set_IdIp kServerIdIpTable;
// Permitted ID set may be dynamically updated at runtime
set_Id kServerPermittedIdSet;

char kKgcPublicKeyPath[MAX_PATH_LENGTH] = {0};
char kServerPublicKeyPath[MAX_PATH_LENGTH] = {0};
char kServerPrivateKeyPath[MAX_PATH_LENGTH] = {0};
char kServerIdIpDatabasePath[MAX_PATH_LENGTH] = {0};
char kServerPermittedIdsDatabasePath[MAX_PATH_LENGTH] = {0};

pthread_mutex_t kServerPermittedIdsMutex;

bool InitializeGlobals(const char *config_file_path);
void FreeGlobals();

#endif