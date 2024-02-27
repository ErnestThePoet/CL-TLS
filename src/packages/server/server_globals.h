#ifndef SERVER_GLOBALS_H_
#define SERVER_GLOBALS_H_

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#include <pthread.h>

#include <common/def.h>
#include <util/log.h>
#include <util/util.h>

#include <database/idip.h>
#include <database/permitted_ids.h>

#include "server_args.h"

extern uint64_t kSocketBlockSize;

extern uint8_t kServerIdentity[ENTITY_IDENTITY_LENGTH];
extern uint8_t kKgcPublicKey[CLTLS_ENTITY_PUBLIC_KEY_LENGTH];
extern uint8_t kServerPublicKey[CLTLS_ENTITY_PUBLIC_KEY_LENGTH];
extern uint8_t kServerPrivateKey[CLTLS_ENTITY_PRIVATE_KEY_LENGTH];

extern set_CipherSuite kServerCipherSuiteSet;
// ID/IP table is manually maintained in a file which is loaded
// at startup
extern set_IdIp kServerIdIpTable;
// Permitted ID set may be dynamically updated at runtime
extern set_Id kServerPermittedIdSet;

extern char kKgcPublicKeyPath[MAX_PATH_LENGTH];
extern char kServerPublicKeyPath[MAX_PATH_LENGTH];
extern char kServerPrivateKeyPath[MAX_PATH_LENGTH];
extern char kServerIdIpDatabasePath[MAX_PATH_LENGTH];
extern char kServerPermittedIdsDatabasePath[MAX_PATH_LENGTH];

extern pthread_mutex_t kServerPermittedIdsMutex;

bool InitializeGlobals(const ServerArgs *server_args);
void FreeGlobals();

#endif