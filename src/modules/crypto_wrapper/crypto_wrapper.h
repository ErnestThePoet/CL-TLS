#ifndef CRYPTO_WRAPPER_H_
#define CRYPTO_WRAPPER_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef struct
{
    void *(*Init)(void);
    int (*Update)(void *ctx, const uint8_t *in, size_t inlen);
    int (*Final)(void *ctx, uint8_t *out);
    void (*FreeCtx)(void *ctx);
    int (*Hash)(const uint8_t *in, size_t inlen, uint8_t *out);
} HashScheme;

typedef struct
{
    int (*Encrypt)(const uint8_t *m, size_t mlen,
                   uint8_t *c, size_t *clen,
                   const uint8_t *ad, size_t adlen,
                   const uint8_t *k,
                   void *extra1,
                   void *extra2);
    int (*Decrypt)(const uint8_t *c, size_t clen,
                   uint8_t *m, size_t *mlen,
                   const uint8_t *ad, size_t adlen,
                   const uint8_t *k,
                   void *extra1,
                   void *extra2);
} AeadScheme;

#endif