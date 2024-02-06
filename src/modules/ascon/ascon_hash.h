#ifndef ASCON_HASH_H_
#define ASCON_HASH_H_

#include <pthread.h>

#include <openssl/evp.h>
#include <openssl/extra/digest_internal.h>

typedef union
{
    uint64_t x[5];
    uint32_t w[5][2];
    uint8_t b[5][8];
} ascon_state_t;

typedef struct
{
    ascon_state_t st;
    uint8_t prev_length;
    uint8_t prev[8];
} ascon_hash_state_t;

inline int AsconHash384(unsigned char *out, const unsigned char *in,
                        unsigned long long inlen);

static void AsconHashInit(EVP_MD_CTX *ctx);
static void AsconHashUpdate(EVP_MD_CTX *ctx, const void *data, size_t count);
static void AsconHashFinal(EVP_MD_CTX *ctx, uint8_t *md);

static void InitEvpAsconHash();

const EVP_MD *EVP_AsconHash();

#endif