#include "ascon_hash_wrapper.h"

void *AsconHashAInit(void)
{
    ascon_hash_state_t *ctx = malloc(sizeof(ascon_hash_state_t));
    if (ctx == NULL)
    {
        return NULL;
    }

    ascon_hash_init(ctx);
    return (void *)ctx;
}

int AsconHashAUpdate(void *ctx, const uint8_t *in, size_t inlen)
{
    ascon_hash_update((ascon_hash_state_t *)ctx, in, inlen);
    return 1;
}

int AsconHashAFinal(void *ctx, uint8_t *out)
{
    ascon_hash_final((ascon_hash_state_t *)ctx, out, ASCON_HASHA_OUTPUT_SIZE);
    return 1;
}

void AsconHashAFreeCtx(void *ctx)
{
    if (ctx != NULL)
    {
        free(ctx);
    }
}

int AsconHashAHash(const uint8_t *in, size_t inlen, uint8_t *out)
{
    return crypto_hash(out, in, inlen);
}