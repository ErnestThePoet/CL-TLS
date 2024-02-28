#include "ascon128a_wrapper.h"

// extra1 is used as npub
static int Ascon128AEncrypt(const uint8_t *m, size_t mlen,
                            uint8_t *c, size_t *clen,
                            const uint8_t *ad, size_t adlen,
                            const uint8_t *k,
                            void *extra1,
                            void *extra2)
{
    (void)extra2;

    unsigned long long clen_ull = 0;

    int result = AsconAeadEncrypt(
        c, &clen_ull, m, mlen, ad, adlen, NULL, (const unsigned char *)extra1, k);

    *clen = clen_ull;

    return !result;
}

// extra1 is used as npub
static int Ascon128ADecrypt(const uint8_t *c, size_t clen,
                            uint8_t *m, size_t *mlen,
                            const uint8_t *ad, size_t adlen,
                            const uint8_t *k,
                            void *extra1,
                            void *extra2)
{
    (void)extra2;

    unsigned long long mlen_ull = 0;

    int result = AsconAeadDecrypt(
        m, &mlen_ull, NULL, c, clen, ad, adlen, (const unsigned char *)extra1, k);

    *mlen = mlen_ull;

    return !result;
}

static const AeadScheme kAeadSchemeAscon128A_ = {
    .Encrypt = Ascon128AEncrypt,
    .Decrypt = Ascon128ADecrypt,
    .key_size = 16,
    .npub_iv_size = 16};

const AeadScheme *kAeadSchemeAscon128A = &kAeadSchemeAscon128A_;