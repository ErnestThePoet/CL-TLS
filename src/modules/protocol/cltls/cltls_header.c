#include "cltls_header.h"

const char *GetCltlsErrorMessage(const uint8_t error_code)
{
    switch (error_code)
    {
    case CLTLS_ERROR_IDENTITY_NOT_PERMITTED:
        return "The other party reports the identity is not permitted(IDENTITY_NOT_PERMITTED)";
    default:
        return "";
    }
}