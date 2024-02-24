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

uint8_t kClientIdentity[ENTITY_IDENTITY_LENGTH] = {0};
uint8_t kKgcPublicKey[CLTLS_ENTITY_PUBLIC_KEY_LENGTH] = {0};
uint8_t kClientPublicKey[CLTLS_ENTITY_PUBLIC_KEY_LENGTH] = {0};
uint8_t kClientPrivateKey[CLTLS_ENTITY_PRIVATE_KEY_LENGTH] = {0};

set_CipherSuite kClientCipherSuiteSet;
// ID/IP table is manually maintained in a file which is loaded
// at startup
set_IdIp kClientIdIpTable;

char kKgcPublicKeyPath[MAX_PATH_LENGTH] = {0};
char kClientPublicKeyPath[MAX_PATH_LENGTH] = {0};
char kClientPrivateKeyPath[MAX_PATH_LENGTH] = {0};
char kClientIdIpDatabasePath[MAX_PATH_LENGTH] = {0};

bool InitializeGlobals(const ClientArgs *client_args);
void FreeGlobals();

#endif