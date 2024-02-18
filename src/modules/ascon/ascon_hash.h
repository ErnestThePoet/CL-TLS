#ifndef ASCON_HASH_H_
#define ASCON_HASH_H_

#include <stdint.h>

#include <pthread.h>

#include <openssl/evp.h>
#include <openssl/extra/digest_internal.h>

#define ASCON_HASH_RATE 8
#define ASCON_HASHA_OUTPUT_SIZE 32

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

extern int crypto_hash(unsigned char *out, const unsigned char *in,
                       unsigned long long inlen);

extern void ascon_hash_init(ascon_hash_state_t *s);
extern void ascon_hash_update(ascon_hash_state_t *s,
                              const uint8_t *in,
                              uint64_t inlen);
extern void ascon_hash_final(ascon_hash_state_t *s,
                             uint8_t *out,
                             uint64_t outlen);

inline int AsconHash384(unsigned char *out, const unsigned char *in,
                        unsigned long long inlen)
{
    return crypto_hash(out, in, inlen);
}

const EVP_MD *EVP_AsconHash();

#endif