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
    kLogLevel = LOG_LEVEL_INFO;

    if (argc != 2)
    {
        LogError("Invalid arguments");
        fputs("Usage: cltls_misc_initializer <path-to-store-keypair>\n", stderr);
        return EXIT_FAILURE;
    }

    // pre allocate space for full public key and private key
    uint8_t public_key[CLTLS_ENTITY_PUBLIC_KEY_LENGTH] = {0};
    uint8_t private_key[CLTLS_ENTITY_PRIVATE_KEY_LENGTH] = {0};

    ED25519_keypair(public_key, private_key);
    ED25519_keypair(public_key + CLTLS_ENTITY_PKA_LENGTH,
                    private_key + CLTLS_ENTITY_SKA_LENGTH);

    uint8_t id_pkab[CLTLS_ID_PKAB_LENGTH] = {0};

    BindIdPkaPkb(kKgcIdentity,
                 public_key,
                 public_key + CLTLS_ENTITY_PKA_LENGTH,
                 id_pkab);

    if (!CltlsSign(public_key + CLTLS_ENTITY_PKA_LENGTH + CLTLS_ENTITY_PKB_LENGTH,
                   id_pkab,
                   CLTLS_ID_PKAB_LENGTH,
                   private_key))
    {
        LogError("CltlsSign() for |id_pkab| failed");
        return EXIT_FAILURE;
    }

    char file_path[MAX_PATH_LENGTH] = {0};
    strcpy(file_path, argv[1]);
    strcat(file_path, "/pubkey.key");

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
    strcat(file_path, "/privkey.key");

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

    LogSuccess("Successfully generated keypair for KGC.\nLocate them in %s", argv[1]);

    return EXIT_SUCCESS;
}