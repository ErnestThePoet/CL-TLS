#include "util.h"

bool IdentityHex2Bin(const char *identity_hex, uint8_t *identity_bin)
{
    for (int i = 0; i < ENTITY_IDENTITY_LENGTH; i++)
    {
        if (sscanf(identity_hex + 2 * i, "%02hhX", identity_bin + i) != 1)
        {
            return false;
        }
    }

    return true;
}

void IdentityBin2Hex(const uint8_t *identity_bin, char *identity_hex)
{
    for (int i = 0; i < ENTITY_IDENTITY_LENGTH; i++)
    {
        sprintf(identity_hex + i * 2, "%02hhX", identity_bin[i]);
    }
}