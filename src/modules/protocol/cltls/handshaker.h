#ifndef HANDSHAKER_H_
#define HANDSHAKER_H_

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include <common/def.h>
#include <util/log.h>
#include <util/byte_vec.h>
#include <util/util.h>
#include <socket/tcp/tcp.h>

#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/curve25519.h>
#include <openssl/hmac.h>
#include <openssl/hkdf.h>
#include <crypto_wrapper/crypto_wrapper.h>
#include <crypto_wrapper/get_schemes.h>

#include <database/idip.h>
#include <database/permitted_ids.h>

#include "cltls_header.h"

typedef struct
{
    uint8_t cipher_suite;
} CipherSuite;
#define P
#define T CipherSuite
#include <set.h>

typedef struct
{
    AeadScheme *aead;
    uint8_t client_key[MAX_ENC_KEY_LENGTH];
    uint8_t server_key[MAX_ENC_KEY_LENGTH];
    uint8_t client_npub_iv[MAX_NPUB_IV_LENGTH];
    uint8_t server_npub_iv[MAX_NPUB_IV_LENGTH];
} HandshakeResult;

#endif