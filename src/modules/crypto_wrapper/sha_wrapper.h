#ifndef SHA_WRAPPER_H_
#define SHA_WRAPPER_H_

#include <stdlib.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/mem.h>

#include "crypto_wrapper.h"

void *Sha256Init(void);
int Sha256Update(void *ctx, const uint8_t *in, size_t inlen);
int Sha256Final(void *ctx, uint8_t *out);
void Sha256FreeCtx(void *ctx);

HashScheme kHashSchemeSha256_ = {
    .Init = Sha256Init,
    .Update = Sha256Update,
    .Final = Sha256Final,
    .FreeCtx = Sha256FreeCtx};

HashScheme *kHashSchemeSha256 = &kHashSchemeSha256_;

#endif