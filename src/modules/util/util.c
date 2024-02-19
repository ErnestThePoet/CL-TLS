#include "util.h"

bool Hex2Bin(const char *hex, uint8_t *bin, const size_t bin_size)
{
    for (int i = 0; i < bin_size; i++)
    {
        if (sscanf(hex + 2 * i, "%02hhX", bin + i) != 1)
        {
            return false;
        }
    }

    return true;
}

void Bin2Hex(const uint8_t *bin, char *hex, const size_t bin_size)
{
    for (int i = 0; i < bin_size; i++)
    {
        sprintf(hex + i * 2, "%02hhX", bin[i]);
    }
}