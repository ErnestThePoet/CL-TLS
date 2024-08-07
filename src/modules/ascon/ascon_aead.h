#ifndef ASCON_AEAD_H_
#define ASCON_AEAD_H_

extern int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                               const unsigned char *m, unsigned long long mlen,
                               const unsigned char *ad, unsigned long long adlen,
                               const unsigned char *nsec, const unsigned char *npub,
                               const unsigned char *k);

extern int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                               unsigned char *nsec, const unsigned char *c,
                               unsigned long long clen, const unsigned char *ad,
                               unsigned long long adlen, const unsigned char *npub,
                               const unsigned char *k);

inline int AsconAeadEncrypt(unsigned char *c, unsigned long long *clen,
                            const unsigned char *m, unsigned long long mlen,
                            const unsigned char *ad, unsigned long long adlen,
                            const unsigned char *nsec, const unsigned char *npub,
                            const unsigned char *k)
{
    return crypto_aead_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k);
}

inline int AsconAeadDecrypt(unsigned char *m, unsigned long long *mlen,
                            unsigned char *nsec, const unsigned char *c,
                            unsigned long long clen, const unsigned char *ad,
                            unsigned long long adlen, const unsigned char *npub,
                            const unsigned char *k)
{
    return crypto_aead_decrypt(m, mlen, nsec, c, clen, ad, adlen, npub, k);
}

#endif