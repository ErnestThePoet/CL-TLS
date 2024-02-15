#include "server_globals.h"

static int CipherSuiteCmp(CipherSuite *a, CipherSuite *b)
{
    return a->cipher_suite == b->cipher_suite
               ? 0
               : (a->cipher_suite > b->cipher_suite ? 1 : -1);
}

bool InitializeGlobals(const char *config_file_path)
{
    FILE *config_file_fp = fopen(config_file_path, "r");
    if (config_file_fp == NULL)
    {
        LogError("Failed to open config file %s", config_file_path);
        return false;
    }

    char server_id_hex[CLTLS_IDENTITY_LENGTH * 2 + 1] = {0};

    if (fscanf(config_file_fp,
               "IDENTITY=%64s\n",
               server_id_hex) != 1)
    {
        LogError("Error loading config file: failed to read IDENTITY");
        fclose(config_file_fp);
        return false;
    }

    for (int i = 0; i < CLTLS_IDENTITY_LENGTH; i++)
    {
        if (sscanf(server_id_hex + 2 * i, "%02hhX", kServerIdentity + i) != 1)
        {
            LogError("Error loading config file: invalid IDENTITY value");
            fclose(config_file_fp);
            return false;
        }
    }

    if (fscanf(config_file_fp,
               "IDIP_DATABASE=%59s\n",
               kServerIdIpDatabasePath) != 1)
    {
        LogError("Error loading config file: failed to read IDIP_DATABASE");
        fclose(config_file_fp);
        return false;
    }

    if (!CreateIdIpTableFromFile(
            kServerIdIpDatabasePath, &kServerIdIpTable))
    {
        return false;
    }

    if (fscanf(config_file_fp,
               "PERMITTED_IDS_DATABASE=%59s\n",
               kServerPermittedIdsDatabasePath) != 1)
    {
        LogError("Error loading config file: failed to read PERMITTED_IDS_DATABASE");
        fclose(config_file_fp);
        return false;
    }

    if (!CreatePermittedIdSetFromFile(
            kServerPermittedIdsDatabasePath, &kServerPermittedIdSet))
    {
        return false;
    }

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