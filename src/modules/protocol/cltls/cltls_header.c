#include "cltls_header.h"

const char *GetCltlsErrorMessage(const uint8_t error_code)
{
    switch (error_code)
    {
    case CLTLS_ERROR_INTERNAL_EXECUTION_ERROR:
        return "ERROR_INTERNAL_EXECUTION_ERROR";
    case CLTLS_ERROR_UNEXPECTED_MSG_TYPE:
        return "ERROR_UNEXPECTED_MSG_TYPE";
    case CLTLS_ERROR_INVALID_APPLICATION_LAYER_PROTOCOL:
        return "ERROR_INVALID_APPLICATION_LAYER_PROTOCOL";
    case CLTLS_ERROR_IDENTITY_NOT_PERMITTED:
        return "ERROR_IDENTITY_NOT_PERMITTED";
    case CLTLS_ERROR_NO_SUPPORTED_CIPHER_SUITE:
        return "ERROR_NO_SUPPORTED_CIPHER_SUITE";
    case CLTLS_ERROR_INVALID_PUBLIC_KEY_LENGTH:
        return "ERROR_INVALID_PUBLIC_KEY_LENGTH";
    case CLTLS_ERROR_PUBLIC_KEY_VERIFY_FAILED:
        return "ERROR_PUBLIC_KEY_VERIFY_FAILED";
    case CLTLS_ERROR_INVALID_TRAFFIC_SIGNATURE_LENGTH:
        return "ERROR_INVALID_TRAFFIC_SIGNATURE_LENGTH";
    case CLTLS_ERROR_TRAFFIC_SIGNATURE_VERIFY_FAILED:
        return "ERROR_TRAFFIC_SIGNATURE_VERIFY_FAILED";
    default:
        return "";
    }
}

void BindIdentityPka(const uint8_t *identity, const uint8_t *pka, uint8_t *out)
{
    memcpy(out, identity, ENTITY_IDENTITY_LENGTH);
    memcpy(out + ENTITY_IDENTITY_LENGTH, pka, CLTLS_ENTITY_PUBLIC_KEY_PKA_LENGTH);
}