#include "ascon_hash.h"

extern int crypto_hash(unsigned char *out, const unsigned char *in,
                       unsigned long long inlen);

inline int ascon_hash(unsigned char *out, const unsigned char *in,
                      unsigned long long inlen)
{
    return crypto_hash(out, in, inlen);
}