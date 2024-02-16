#ifndef ASCON_HASH_WRAPPER_H_
#define ASCON_HASH_WRAPPER_H_

#include <stdlib.h>
#include <stdbool.h>
#include <ascon/ascon_hash.h>

#include "crypto_wrapper.h"

void *AsconHashAInit(void);
int AsconHashAUpdate(void *ctx, const uint8_t *in, size_t inlen);
int AsconHashAFinal(void *ctx, uint8_t *out);
void AsconHashAFreeCtx(void *ctx);

HashScheme kHashSchemeAsconHashA = {
    .Init = AsconHashAInit,
    .Update = AsconHashAUpdate,
    .Final = AsconHashAFinal,
    .FreeCtx = AsconHashAFreeCtx};

#endif