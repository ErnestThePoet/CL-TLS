#include "ascon_hash.h"

extern int crypto_hash(unsigned char *out, const unsigned char *in,
                       unsigned long long inlen);

inline int AsconHash384(unsigned char *out, const unsigned char *in,
                        unsigned long long inlen)
{
    return crypto_hash(out, in, inlen);
}