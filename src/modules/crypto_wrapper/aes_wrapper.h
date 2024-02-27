#ifndef AES_WRAPPER_H_
#define AES_WRAPPER_H_

#include <stdint.h>
#include <stdbool.h>

#include <openssl/cipher.h>

#include "crypto_wrapper.h"

#define ERROR_EVP_CTX_FREE_RETURN \
    do                            \
    {                             \
        EVP_CIPHER_CTX_free(ctx); \
        return 0;                 \
    } while (false)

extern const AeadScheme *kAeadSchemeAes128Gcm;

#endif