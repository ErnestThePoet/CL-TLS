#ifndef GET_SCHEMES_H_
#define GET_SCHEMES_H_

#include <stdint.h>

#include <ascon/ascon_hash.h>
#include <openssl/evp.h>
#include <openssl/digest.h>

#include <protocol/cltls/cltls_header.h>

#include "crypto_wrapper.h"
#include "ascon_hash_wrapper.h"
#include "crypto_wrapper/sha_wrapper.h"
#include "crypto_wrapper/ascon128a_wrapper.h"
#include "crypto_wrapper/aes_wrapper.h"

void GetCryptoSchemes(const uint8_t cipher_suite,
                      const HashScheme **hash_ret,
                      const AeadScheme **aead_ret,
                      const EVP_MD **hmac_hkdf_md_ret);

#endif