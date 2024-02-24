#include "client_globals.h"

bool InitializeGlobals(const ClientArgs *client_args)
{
    // Read config file
    FILE *config_file_fp = fopen(client_args->config_file_path, "r");
    if (config_file_fp == NULL)
    {
        LogError("Failed to open config file %s", client_args->config_file_path);
        return false;
    }

    char client_id_hex[ENTITY_IDENTITY_LENGTH * 2 + 1] = {0};

    if (fscanf(config_file_fp,
               "IDENTITY=%64s\n",
               client_id_hex) != 1)
    {
        LogError("Error loading config file: failed to read IDENTITY");
        fclose(config_file_fp);
        return false;
    }

    if (fscanf(config_file_fp,
               "PUBLIC_KEY=%79s\n",
               kClientPublicKeyPath) != 1)
    {
        LogError("Error loading config file: failed to read PUBLIC_KEY");
        fclose(config_file_fp);
        return false;
    }

    if (fscanf(config_file_fp,
               "PRIVATE_KEY=%79s\n",
               kClientPrivateKeyPath) != 1)
    {
        LogError("Error loading config file: failed to read PRIVATE_KEY");
        fclose(config_file_fp);
        return false;
    }

    if (fscanf(config_file_fp,
               "KGC_PUBLIC_KEY=%79s\n",
               kKgcPublicKeyPath) != 1)
    {
        LogError("Error loading config file: failed to read KGC_PUBLIC_KEY");
        fclose(config_file_fp);
        return false;
    }

    if (fscanf(config_file_fp,
               "IDIP_DATABASE=%79s\n",
               kClientIdIpDatabasePath) != 1)
    {
        LogError("Error loading config file: failed to read IDIP_DATABASE");
        fclose(config_file_fp);
        return false;
    }

    fclose(config_file_fp);

    // Load client identity
    if (!Hex2Bin(client_id_hex, kClientIdentity, ENTITY_IDENTITY_LENGTH))
    {
        LogError("Error loading config file: invalid IDENTITY value");
        fclose(config_file_fp);
        return false;
    }

    // Read KGC public key
    FILE *key_fp = fopen(kKgcPublicKeyPath, "rb");
    if (key_fp == NULL)
    {
        LogError("Failed to open KGC public key file %s", kKgcPublicKeyPath);
        return false;
    }

    if (fread(kKgcPublicKey, 1, CLTLS_ENTITY_PUBLIC_KEY_LENGTH, key_fp) !=
        CLTLS_ENTITY_PUBLIC_KEY_LENGTH)
    {
        LogError("Failed to read a valid KGC public key from file %s",
                 kKgcPublicKeyPath);
        return false;
    }

    fclose(key_fp);

    if (!client_args->register_client)
    {
        // Read client public key
        key_fp = fopen(kClientPublicKeyPath, "rb");
        if (key_fp == NULL)
        {
            LogError("Failed to open client public key file %s", kClientPublicKeyPath);
            return false;
        }

        if (fread(kClientPublicKey, 1, CLTLS_ENTITY_PUBLIC_KEY_LENGTH, key_fp) !=
            CLTLS_ENTITY_PUBLIC_KEY_LENGTH)
        {
            LogError("Failed to read a valid client public key from file %s",
                     kClientPublicKeyPath);
            return false;
        }

        fclose(key_fp);

        // Read client private key
        key_fp = fopen(kClientPrivateKeyPath, "rb");
        if (key_fp == NULL)
        {
            LogError("Failed to open client private key file %s",
                     kClientPrivateKeyPath);
            return false;
        }

        if (fread(kClientPrivateKey, 1, CLTLS_ENTITY_PRIVATE_KEY_LENGTH, key_fp) !=
            CLTLS_ENTITY_PRIVATE_KEY_LENGTH)
        {
            LogError("Failed to read a valid client private key from file %s",
                     kClientPrivateKeyPath);
            return false;
        }

        fclose(key_fp);
    }

    // Read ID/IP table
    if (!CreateIdIpTableFromFile(
            kClientIdIpDatabasePath, &kClientIdIpTable))
    {
        return false;
    }

    // Create supported cipher suite set
    kClientCipherSuiteSet = set_CipherSuite_init(CipherSuiteCmp);
    set_CipherSuite_insert(
        &kClientCipherSuiteSet,
        (CipherSuite){.cipher_suite = CLTLS_CIPHER_ASCON128A_ASCONHASHA});
    set_CipherSuite_insert(
        &kClientCipherSuiteSet,
        (CipherSuite){.cipher_suite = CLTLS_CIPHER_ASCON128A_SHA256});
    set_CipherSuite_insert(
        &kClientCipherSuiteSet,
        (CipherSuite){.cipher_suite = CLTLS_CIPHER_AES128GCM_ASCONHASHA});
    set_CipherSuite_insert(
        &kClientCipherSuiteSet,
        (CipherSuite){.cipher_suite = CLTLS_CIPHER_AES128GCM_SHA256});

    return true;
}

void FreeGlobals()
{
    FreeIdIpTable(&kClientIdIpTable);
    set_CipherSuite_free(&kClientCipherSuiteSet);
}