#include "idip.h"

static int IdIpCmp(IdIp *a, IdIp *b)
{
    return memcmp(a->id, b->id, CLTLS_IDENTITY_LENGTH);
}

bool CreateIdIpTableFromFile(const char *file_path, set_IdIp *table_ret)
{
    FILE *idip_database_fp = fopen(file_path, "r");
    if (idip_database_fp == NULL)
    {
        LogError("Failed to open ID/IP database file %s", file_path);
        return false;
    }

    set_IdIp table = set_IdIp_init(IdIpCmp);

    IdIp current;
    while (true)
    {
        int read_result = fscanf(idip_database_fp, "%02hhX", current.id);
        if (read_result == EOF)
        {
            break;
        }

        if (read_result != 1)
        {
            LogError("Error loading ID/IP database: invalid identity value");
            fclose(idip_database_fp);
            return false;
        }

        for (int i = 0; i < CLTLS_IDENTITY_LENGTH - 1; i++)
        {
            if (fscanf(idip_database_fp, "%02hhX", current.id + 1 + i) != 1)
            {
                LogError("Error loading ID/IP database: invalid identity value");
                fclose(idip_database_fp);
                return false;
            }
        }

        if (fscanf(idip_database_fp, "%15s", current.ip) != 1)
        {
            LogError("Error loading ID/IP database: invalid IP value");
            fclose(idip_database_fp);
            return false;
        }

        set_IdIp_insert(&table, current);
    }

    fclose(idip_database_fp);

    *table_ret = table;

    return true;
}

void FreeIdIpTable(set_IdIp *table)
{
    set_IdIp_free(table);
}