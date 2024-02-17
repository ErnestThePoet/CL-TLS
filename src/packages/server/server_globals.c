#include "server_globals.h"

static int CipherSuiteCmp(CipherSuite *a, CipherSuite *b)
{
    return a->cipher_suite == b->cipher_suite
               ? 0
               : (a->cipher_suite > b->cipher_suite ? 1 : -1);
}

bool InitializeGlobals(const char *config_file_path)
{
    // Read config file
    FILE *config_file_fp = fopen(config_file_path, "r");
    if (config_file_fp == NULL)
    {
        LogError("Failed to open config file %s", config_file_path);
        return false;
    }

    char server_id_hex[ENTITY_IDENTITY_LENGTH * 2 + 1] = {0};

    if (fscanf(config_file_fp,
               "IDENTITY=%64s\n",
               server_id_hex) != 1)
    {
        LogError("Error loading config file: failed to read IDENTITY");
        fclose(config_file_fp);
        return false;
    }

    if (fscanf(config_file_fp,
               "PUBLIC_KEY=%79s\n",
               kServerPublicKeyPath) != 1)
    {
        LogError("Error loading config file: failed to read PUBLIC_KEY");
        fclose(config_file_fp);
        return false;
    }

    if (fscanf(config_file_fp,
               "PRIVATE_KEY=%79s\n",
               kServerPrivateKeyPath) != 1)
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
               kServerIdIpDatabasePath) != 1)
    {
        LogError("Error loading config file: failed to read IDIP_DATABASE");
        fclose(config_file_fp);
        return false;
    }

    if (fscanf(config_file_fp,
               "PERMITTED_IDS_DATABASE=%79s\n",
               kServerPermittedIdsDatabasePath) != 1)
    {
        LogError("Error loading config file: failed to read PERMITTED_IDS_DATABASE");
        fclose(config_file_fp);
        return false;
    }

    fclose(config_file_fp);

    // Load server identity
    if (!IdentityHex2Bin(server_id_hex, kServerIdentity))
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

    // Read server public key
    key_fp = fopen(kServerPublicKeyPath, "rb");
    if (key_fp == NULL)
    {
        LogError("Failed to open server public key file %s", kServerPublicKeyPath);
        return false;
    }

    if (fread(kServerPublicKey, 1, CLTLS_ENTITY_PUBLIC_KEY_LENGTH, key_fp) !=
        CLTLS_ENTITY_PUBLIC_KEY_LENGTH)
    {
        LogError("Failed to read a valid server public key from file %s",
                 kServerPublicKeyPath);
        return false;
    }

    fclose(key_fp);

    // Read server private key
    key_fp = fopen(kServerPrivateKeyPath, "rb");
    if (key_fp == NULL)
    {
        LogError("Failed to open server private key file %s",
                 kServerPrivateKeyPath);
        return false;
    }

    if (fread(kServerPrivateKey, 1, CLTLS_ENTITY_PRIVATE_KEY_LENGTH, key_fp) !=
        CLTLS_ENTITY_PRIVATE_KEY_LENGTH)
    {
        LogError("Failed to read a valid server private key from file %s",
                 kServerPrivateKeyPath);
        return false;
    }

    fclose(key_fp);

    // Read ID/IP table
    if (!CreateIdIpTableFromFile(
            kServerIdIpDatabasePath, &kServerIdIpTable))
    {
        return false;
    }

    // Read permitted ID set
    if (!CreatePermittedIdSetFromFile(
            kServerPermittedIdsDatabasePath, &kServerPermittedIdSet))
    {
        return false;
    }

    // Create supported cipher suite set
    kServerCipherSuiteSet = set_CipherSuite_init(CipherSuiteCmp);
    set_CipherSuite_insert(
        &kServerCipherSuiteSet,
        (CipherSuite){.cipher_suite = CLTLS_CIPHER_ASCON128A_ASCONHASHA});
    set_CipherSuite_insert(
        &kServerCipherSuiteSet,
        (CipherSuite){.cipher_suite = CLTLS_CIPHER_ASCON128A_SHA256});
    set_CipherSuite_insert(
        &kServerCipherSuiteSet,
        (CipherSuite){.cipher_suite = CLTLS_CIPHER_AES128GCM_ASCONHASHA});
    set_CipherSuite_insert(
        &kServerCipherSuiteSet,
        (CipherSuite){.cipher_suite = CLTLS_CIPHER_AES128GCM_SHA256});

    return true;
}

void FreeGlobals()
{
    FreeIdIpTable(&kServerIdIpTable);
    FreePermittedIdSet(&kServerPermittedIdSet);
    set_CipherSuite_free(&kServerCipherSuiteSet);
}