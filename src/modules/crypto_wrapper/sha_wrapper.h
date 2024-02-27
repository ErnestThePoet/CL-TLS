#ifndef SHA_WRAPPER_H_
#define SHA_WRAPPER_H_

#include <stdlib.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/mem.h>

#include "crypto_wrapper.h"

extern const HashScheme *kHashSchemeSha256;

#endif