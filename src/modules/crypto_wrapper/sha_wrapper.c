#include "sha_wrapper.h"

void *Sha256Init(void)
{
    SHA256_CTX *ctx = malloc(sizeof(SHA256_CTX));
    if (ctx == NULL)
    {
        return NULL;
    }

    SHA256_Init(ctx);
}

int Sha256Update(void *ctx, const uint8_t *in, size_t inlen)
{
    return SHA256_Update(ctx, in, inlen);
}

int Sha256Final(void *ctx, uint8_t *out)
{
    return SHA256_Final(out, ctx);
}

void Sha256FreeCtx(void *ctx)
{
    if (ctx != NULL)
    {
        OPENSSL_cleanse(ctx, sizeof(SHA256_CTX));
        free(ctx);
    }
}