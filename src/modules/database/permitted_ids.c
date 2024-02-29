#include "permitted_ids.h"

static int IdCmp(Id *a, Id *b)
{
    return memcmp(a->id, b->id, ENTITY_IDENTITY_LENGTH);
}

bool CreatePermittedIdSetFromFile(const char *file_path, set_Id *set_ret)
{
    FILE *permitted_ids_database_fp = fopen(file_path, "r");
    if (permitted_ids_database_fp == NULL)
    {
        LogError("Failed to open permitted IDs database file %s", file_path);
        return false;
    }

    set_Id set_ = set_Id_init(IdCmp);

    Id current;
    while (true)
    {
        int read_result = fscanf(permitted_ids_database_fp, "%02hhX", current.id);
        if (read_result == EOF)
        {
            break;
        }

        if (read_result != 1)
        {
            LogError("Error loading permitted IDs database: invalid identity value");
            fclose(permitted_ids_database_fp);
            return false;
        }

        for (int i = 0; i < ENTITY_IDENTITY_LENGTH - 1; i++)
        {
            if (fscanf(permitted_ids_database_fp, "%02hhX", current.id + 1 + i) != 1)
            {
                LogError("Error loading permitted IDs database: invalid identity value");
                fclose(permitted_ids_database_fp);
                return false;
            }
        }

        set_Id_insert(&set_, current);
    }

    fclose(permitted_ids_database_fp);

    *set_ret = set_;

    return true;
}

void FreePermittedIdSet(set_Id *set_)
{
    set_Id_free(set_);
}