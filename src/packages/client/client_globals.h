#ifndef CLIENT_GLOBALS_H_
#define CLIENT_GLOBALS_H_

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#include <common/def.h>
#include <util/log.h>
#include <util/util.h>

#include <database/idip.h>

#include "client_args.h"

extern uint64_t kSocketBlockSize;

extern uint8_t kClientIdentity[ENTITY_IDENTITY_LENGTH];
extern uint8_t kKgcPublicKey[CLTLS_ENTITY_PUBLIC_KEY_LENGTH];
extern uint8_t kClientPublicKey[CLTLS_ENTITY_PUBLIC_KEY_LENGTH];
extern uint8_t kClientPrivateKey[CLTLS_ENTITY_PRIVATE_KEY_LENGTH];

extern set_CipherSuite kClientCipherSuiteSet;
// ID/IP table is manually maintained in a file which is loaded
// at startup
extern set_IdIp kClientIdIpTable;

extern char kKgcPublicKeyPath[MAX_PATH_LENGTH];
extern char kClientPublicKeyPath[MAX_PATH_LENGTH];
extern char kClientPrivateKeyPath[MAX_PATH_LENGTH];
extern char kClientIdIpDatabasePath[MAX_PATH_LENGTH];

bool InitializeGlobals(const ClientArgs *client_args);
void FreeGlobals();

#endif