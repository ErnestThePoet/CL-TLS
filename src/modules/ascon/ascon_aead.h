#ifndef ASCON_AEAD_H_
#define ASCON_AEAD_H_

inline int AsconAeadEncrypt(unsigned char *c, unsigned long long *clen,
                            const unsigned char *m, unsigned long long mlen,
                            const unsigned char *ad, unsigned long long adlen,
                            const unsigned char *nsec, const unsigned char *npub,
                            const unsigned char *k);

inline int AsconAeadDecrypt(unsigned char *m, unsigned long long *mlen,
                            unsigned char *nsec, const unsigned char *c,
                            unsigned long long clen, const unsigned char *ad,
                            unsigned long long adlen, const unsigned char *npub,
                            const unsigned char *k);

#endif