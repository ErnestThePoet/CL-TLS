#include "ascon_hash.h"

// These three functions are used to construct an EVP_MD 
// for constructing HMAC and HKDF
static void AsconHashInit(EVP_MD_CTX *ctx)
{
    ascon_hash_init(ctx->md_data);
}

static void AsconHashUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    ascon_hash_update(ctx->md_data, data, count);
}

static void AsconHashFinal(EVP_MD_CTX *ctx, uint8_t *md)
{
    ascon_hash_final(ctx->md_data, md, ASCON_HASHA_OUTPUT_SIZE);
}

static EVP_MD kEvpAsconHash;
static pthread_once_t kEvpAsconHashOnce = PTHREAD_ONCE_INIT;

static void InitEvpAsconHash()
{
    kEvpAsconHash.type = NID_sha256; // disguise
    kEvpAsconHash.md_size = ASCON_HASHA_OUTPUT_SIZE;
    kEvpAsconHash.flags = 0;
    kEvpAsconHash.init = AsconHashInit;
    kEvpAsconHash.update = AsconHashUpdate;
    kEvpAsconHash.final = AsconHashFinal;
    kEvpAsconHash.block_size = 64;
    kEvpAsconHash.ctx_size = sizeof(ascon_hash_state_t);
}

const EVP_MD *EVP_AsconHash()
{
    pthread_once(&kEvpAsconHashOnce, InitEvpAsconHash);
    return (const EVP_MD *)&kEvpAsconHash;
}