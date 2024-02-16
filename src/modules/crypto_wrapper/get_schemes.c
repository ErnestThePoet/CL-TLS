#include "get_schemes.h"

void GetCryptoSchemes(const uint8_t cipher_suite,
                      const HashScheme **hash_ret,
                      const AeadScheme **aead_ret,
                      const EVP_MD **hmac_hkdf_md_ret)
{
    switch (cipher_suite)
    {
    case CLTLS_CIPHER_ASCON128A_ASCONHASHA:
        *hash_ret = kHashSchemeAsconHashA;
        *aead_ret = kAeadSchemeAscon128A;
        *hmac_hkdf_md_ret = EVP_AsconHash();
        break;
    case CLTLS_CIPHER_ASCON128A_SHA256:
        *hash_ret = kHashSchemeSha256;
        *aead_ret = kAeadSchemeAscon128A;
        *hmac_hkdf_md_ret = EVP_sha256();
        break;
    case CLTLS_CIPHER_AES128GCM_ASCONHASHA:
        *hash_ret = kHashSchemeAsconHashA;
        *aead_ret = kAeadSchemeAes128Gcm;
        *hmac_hkdf_md_ret = EVP_AsconHash();
        break;
    case CLTLS_CIPHER_AES128GCM_SHA256:
        *hash_ret = kHashSchemeSha256;
        *aead_ret = kAeadSchemeAes128Gcm;
        *hmac_hkdf_md_ret = EVP_sha256();
        break;
    default:
        *hash_ret = NULL;
        *aead_ret = NULL;
        *hmac_hkdf_md_ret = NULL;
        break;
    }
}