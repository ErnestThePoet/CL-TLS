/***************************************
 *
 * CLTLS Initializer generates entity
 * public key(self-signatured) and
 * private key for KGC so everything
 * can start working.
 *
 * ************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <common/def.h>
#include <util/log.h>

#include <openssl/bn.h>
#include <openssl/curve25519.h>

#include <protocol/cltls/cltls_header.h>

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        LogError("Invalid arguments");
        fputs("Usage: cltls_misc_initializer <path-to-store-keypair>\n", stderr);
        return EXIT_FAILURE;
    }

    kLogLevel = LOG_LEVEL_INFO;

    BIGNUM *pka_bn = BN_new();
    if (pka_bn == NULL)
    {
        LogError("Memory allocation for |pka_bn| failed");
        return EXIT_FAILURE;
    }

    if (!BN_rand(pka_bn,
                 CLTLS_ENTITY_PKA_LENGTH * 8,
                 BN_RAND_TOP_ANY,
                 BN_RAND_BOTTOM_ANY))
    {
        LogError("BN_rand() for |pka_bn| failed");
        BN_free(pka_bn);
        return EXIT_FAILURE;
    }

    uint8_t pka[CLTLS_ENTITY_PKA_LENGTH] = {0};

    if (!BN_bn2bin_padded(pka,
                          CLTLS_ENTITY_PKA_LENGTH,
                          pka_bn))
    {
        LogError("BN_bn2bin_padded() for |pka| failed");
        BN_free(pka_bn);
        return EXIT_FAILURE;
    }

    BN_free(pka_bn);

    uint8_t binded_id_pka[CLTLS_BINDED_IDENTITY_PKA_LENGTH] = {0};

    BindIdentityPka(kKgcIdentity, pka, binded_id_pka);

    uint8_t public_key[CLTLS_ENTITY_PUBLIC_KEY_LENGTH] = {0};
    uint8_t private_key[CLTLS_ENTITY_PRIVATE_KEY_LENGTH] = {0};

    ED25519_keypair(public_key, private_key);

    memcpy(public_key + CLTLS_ENTITY_PKF_LENGTH, pka, CLTLS_ENTITY_PKA_LENGTH);

    if (!ED25519_sign(public_key + CLTLS_ENTITY_PKF_LENGTH + CLTLS_ENTITY_PKA_LENGTH,
                      binded_id_pka,
                      CLTLS_BINDED_IDENTITY_PKA_LENGTH,
                      private_key))
    {
        LogError("ED25519_sign() for |binded_id_pka| failed");
        return EXIT_FAILURE;
    }

    char file_path[MAX_PATH_LENGTH] = {0};
    strcpy(file_path, argv[1]);
    strcat(file_path, "/pubkey");

    FILE *public_key_fp = fopen(file_path, "wb");
    if (public_key_fp == NULL)
    {
        LogError("Failed to open public key file %s", file_path);
        return EXIT_FAILURE;
    }

    if (fwrite(public_key, 1, CLTLS_ENTITY_PUBLIC_KEY_LENGTH, public_key_fp) !=
        CLTLS_ENTITY_PUBLIC_KEY_LENGTH)
    {
        LogError("Failed to write public key file %s", file_path);
        fclose(public_key_fp);
        return EXIT_FAILURE;
    }

    fclose(public_key_fp);

    strcpy(file_path, argv[1]);
    strcat(file_path, "/privkey");

    FILE *private_key_fp = fopen(file_path, "wb");
    if (private_key_fp == NULL)
    {
        LogError("Failed to open private key file %s", file_path);
        return EXIT_FAILURE;
    }

    if (fwrite(private_key, 1, CLTLS_ENTITY_PRIVATE_KEY_LENGTH, private_key_fp) !=
        CLTLS_ENTITY_PRIVATE_KEY_LENGTH)
    {
        LogError("Failed to write private key file %s", file_path);
        fclose(private_key_fp);
        return EXIT_FAILURE;
    }

    fclose(private_key_fp);

    LogInfo("Successfully generated keypair for KGC.\nLocate them in %s", argv[1]);

    return EXIT_SUCCESS;
}