#include "ascon_hash_wrapper.h"

static void *AsconHashAInit(void)
{
    ascon_hash_state_t *ctx = malloc(sizeof(ascon_hash_state_t));
    if (ctx == NULL)
    {
        return NULL;
    }

    ascon_hash_init(ctx);
    return (void *)ctx;
}

static int AsconHashAUpdate(void *ctx, const uint8_t *in, size_t inlen)
{
    ascon_hash_update((ascon_hash_state_t *)ctx, in, inlen);
    return 1;
}

static int AsconHashAFinal(void *ctx, uint8_t *out)
{
    ascon_hash_final((ascon_hash_state_t *)ctx, out, ASCON_HASHA_OUTPUT_SIZE);
    return 1;
}

static void AsconHashAFreeCtx(void *ctx)
{
    if (ctx != NULL)
    {
        free(ctx);
    }
}

static int AsconHashAHash(const uint8_t *in, size_t inlen, uint8_t *out)
{
    return !crypto_hash(out, in, inlen);
}

static const HashScheme kHashSchemeAsconHashA_ = {
    .Init = AsconHashAInit,
    .Update = AsconHashAUpdate,
    .Final = AsconHashAFinal,
    .FreeCtx = AsconHashAFreeCtx,
    .Hash = AsconHashAHash,
    .hash_size = ASCON_HASHA_OUTPUT_SIZE};

const HashScheme *kHashSchemeAsconHashA = &kHashSchemeAsconHashA_;