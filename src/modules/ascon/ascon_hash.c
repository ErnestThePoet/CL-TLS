#include "ascon_hash.h"

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
    ascon_hash_final(ctx->md_data, md, 32);
}

static EVP_MD kEvpAsconHash;
static pthread_once_t kEvpAsconHashOnce = PTHREAD_ONCE_INIT;

static void InitEvpAsconHash()
{
    kEvpAsconHash.type = NID_sha256; // disguise
    kEvpAsconHash.md_size = 32;
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