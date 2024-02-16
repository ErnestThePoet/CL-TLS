#include "ascon128a_wrapper.h"

int Ascon128AEncrypt(const uint8_t *m, size_t mlen,
                     uint8_t *c, size_t *clen,
                     const uint8_t *ad, size_t adlen,
                     const uint8_t *k,
                     void *extra1,
                     void *extra2)
{
    (void)extra2;
    return AsconAeadEncrypt(
        c, clen, m, mlen, ad, adlen, NULL, (const unsigned char *)extra1, k);
}

int Ascon128ADecrypt(const uint8_t *c, size_t clen,
                     uint8_t *m, size_t *mlen,
                     const uint8_t *ad, size_t adlen,
                     const uint8_t *k,
                     void *extra1,
                     void *extra2)
{
    (void)extra2;
    return AsconAeadDecrypt(
        m, mlen, NULL, c, clen, ad, adlen, (const unsigned char *)extra1, k);
}