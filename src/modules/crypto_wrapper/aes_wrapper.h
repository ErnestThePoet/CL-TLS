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

// extra1 is used as IV
// extra2 is used as IV Length(size_t)
int Aes128GcmEncrypt(const uint8_t *m, size_t mlen,
                     uint8_t *c, size_t *clen,
                     const uint8_t *ad, size_t adlen,
                     const uint8_t *k,
                     void *extra1,
                     void *extra2);

// extra1 is used as IV
// extra2 is used as IV Length(size_t)
int Aes128GcmDecrypt(const uint8_t *c, size_t clen,
                     uint8_t *m, size_t *mlen,
                     const uint8_t *ad, size_t adlen,
                     const uint8_t *k,
                     void *extra1,
                     void *extra2);

const AeadScheme kAeadSchemeAes128Gcm_ = {
    .Encrypt = Aes128GcmEncrypt,
    .Decrypt = Aes128GcmDecrypt,
    .key_size = 16,
    .npub_iv_size = 16};

const AeadScheme *kAeadSchemeAes128Gcm = &kAeadSchemeAes128Gcm_;

#endif