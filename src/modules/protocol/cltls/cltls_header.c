#include "cltls_header.h"

const char *GetCltlsErrorMessage(const uint8_t error_code)
{
    switch (error_code)
    {
    case CLTLS_ERROR_INTERNAL_EXECUTION_ERROR:
        return "INTERNAL_EXECUTION_ERROR";
    case CLTLS_ERROR_UNEXPECTED_MSG_TYPE:
        return "UNEXPECTED_MSG_TYPE";
    case CLTLS_ERROR_INVALID_APPLICATION_LAYER_PROTOCOL:
        return "INVALID_APPLICATION_LAYER_PROTOCOL";
    case CLTLS_ERROR_IDENTITY_NOT_PERMITTED:
        return "IDENTITY_NOT_PERMITTED";
    case CLTLS_ERROR_NO_SUPPORTED_CIPHER_SUITE:
        return "NO_SUPPORTED_CIPHER_SUITE";
    default:
        return "";
    }
}