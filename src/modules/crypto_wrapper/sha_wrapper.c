#include "sha_wrapper.h"

static void *Sha256Init(void)
{
    SHA256_CTX *ctx = malloc(sizeof(SHA256_CTX));
    if (ctx == NULL)
    {
        return NULL;
    }

    SHA256_Init(ctx);

    return ctx;
}

static int Sha256Update(void *ctx, const uint8_t *in, size_t inlen)
{
    return SHA256_Update(ctx, in, inlen);
}

static int Sha256Final(void *ctx, uint8_t *out)
{
    return SHA256_Final(out, ctx);
}

static void Sha256FreeCtx(void *ctx)
{
    if (ctx != NULL)
    {
        OPENSSL_cleanse(ctx, sizeof(SHA256_CTX));
        free(ctx);
    }
}

static int Sha256Hash(const uint8_t *in, size_t inlen, uint8_t *out)
{
    SHA256(in, inlen, out);
    return 1;
}

static const HashScheme kHashSchemeSha256_ = {
    .Init = Sha256Init,
    .Update = Sha256Update,
    .Final = Sha256Final,
    .FreeCtx = Sha256FreeCtx,
    .Hash = Sha256Hash,
    .hash_size = SHA256_DIGEST_LENGTH};

const HashScheme *kHashSchemeSha256 = &kHashSchemeSha256_;