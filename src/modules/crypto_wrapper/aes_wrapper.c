#include "aes_wrapper.h"

int Aes128GcmEncrypt(const uint8_t *m, size_t mlen,
                     uint8_t *c, size_t *clen,
                     const uint8_t *ad, size_t adlen,
                     const uint8_t *k,
                     void *extra1,
                     void *extra2)
{
    uint8_t *iv = (uint8_t *)extra1;
    size_t ivlen = *(size_t *)extra2;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return 0;
    }

    /* Initialise the encryption operation. */
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
    {
        ERROR_EVP_CTX_FREE_RETURN;
    }

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL))
    {
        ERROR_EVP_CTX_FREE_RETURN;
    }

    /* Initialise key and IV */
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, k, iv))
    {
        ERROR_EVP_CTX_FREE_RETURN;
    }

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    int current_length = 0;
    if (ad != NULL && !EVP_EncryptUpdate(ctx, NULL, &current_length, ad, adlen))
    {
        ERROR_EVP_CTX_FREE_RETURN;
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, c, &current_length, m, mlen))
    {
        ERROR_EVP_CTX_FREE_RETURN;
    }

    size_t cipher_length = current_length;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if (1 != EVP_EncryptFinal_ex(ctx, c + cipher_length, &current_length))
    {
        ERROR_EVP_CTX_FREE_RETURN;
    }

    cipher_length += current_length;

    /* Get the tag and concatenate to the end of ciphertext */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, c + cipher_length))
    {
        ERROR_EVP_CTX_FREE_RETURN;
    }

    cipher_length += 16;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    *clen = cipher_length;

    return 1;
}

int Aes128GcmDecrypt(const uint8_t *c, size_t clen,
                     uint8_t *m, size_t *mlen,
                     const uint8_t *ad, size_t adlen,
                     const uint8_t *k,
                     void *extra1,
                     void *extra2)
{
    uint8_t *iv = (uint8_t *)extra1;
    size_t ivlen = *(size_t *)extra2;

    clen -= 16;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    /* Create and initialise the context */
    if (ctx == NULL)
    {
        return 0;
    }

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
    {
        ERROR_EVP_CTX_FREE_RETURN;
    }

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL))
    {
        ERROR_EVP_CTX_FREE_RETURN;
    }

    /* Initialise key and IV */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, k, iv))
    {
        ERROR_EVP_CTX_FREE_RETURN;
    }

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    int current_length = 0;
    if (ad != NULL && !EVP_DecryptUpdate(ctx, NULL, &current_length, ad, adlen))
    {
        ERROR_EVP_CTX_FREE_RETURN;
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (!EVP_DecryptUpdate(ctx, m, &current_length, c, clen))
    {
        ERROR_EVP_CTX_FREE_RETURN;
    }
    size_t plaintext_length = current_length;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, c + clen - 16))
    {
        ERROR_EVP_CTX_FREE_RETURN;
    }

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    int ret = EVP_DecryptFinal_ex(ctx, m + plaintext_length, &current_length);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
        /* Success */
        plaintext_length += current_length;
        *mlen = plaintext_length;
        return 1;
    }
    else
    {
        /* Verify failed */
        return 0;
    }
}