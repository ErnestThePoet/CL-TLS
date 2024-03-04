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
    case CLTLS_ERROR_INVALID_VERIFY_DATA_LENGTH:
        return "ERROR_INVALID_VERIFY_DATA_LENGTH";
    case CLTLS_ERROR_VERIFY_DATA_VERIFY_FAILED:
        return "ERROR_VERIFY_DATA_VERIFY_FAILED";
    case CLTLS_ERROR_SELECTED_CIPHER_SUITE_UNSUPPORTED:
        return "ERROR_SELECTED_CIPHER_SUITE_UNSUPPORTED";
    case CLTLS_ERROR_APPLICATION_LAYER_ERROR:
        return "ERROR_APPLICATION_LAYER_ERROR";
    default:
        return "<UNKNOWN>";
    }
}

void BindIdPkaPkb(const uint8_t *identity,
                  const uint8_t *pka,
                  const uint8_t *pkb, uint8_t *out)
{
    memcpy(out, identity, ENTITY_IDENTITY_LENGTH);
    memcpy(out + ENTITY_IDENTITY_LENGTH,
           pka,
           CLTLS_ENTITY_PKA_LENGTH);
    memcpy(out + ENTITY_IDENTITY_LENGTH + CLTLS_ENTITY_PKA_LENGTH,
           pkb,
           CLTLS_ENTITY_PKB_LENGTH);
}

int CltlsSign(uint8_t *out,
              const uint8_t *message,
              const size_t message_len,
              const uint8_t *private_key)
{
    int result = ED25519_sign(out, message, message_len, private_key);
    if (!result)
    {
        return result;
    }
    return ED25519_sign(out + ED25519_SIGNATURE_LEN,
                        message,
                        message_len,
                        private_key + CLTLS_ENTITY_SKA_LENGTH);
}

int CltlsVerify(const uint8_t *message,
                const size_t message_len,
                const uint8_t *signature,
                const uint8_t *public_key)
{
    int result = ED25519_verify(message, message_len, signature, public_key);
    if (!result)
    {
        return result;
    }
    return ED25519_verify(message,
                          message_len,
                          signature + ED25519_SIGNATURE_LEN,
                          public_key + CLTLS_ENTITY_PKA_LENGTH);
}