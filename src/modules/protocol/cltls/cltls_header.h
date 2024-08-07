#ifndef CLTLS_HEADER_H_
#define CLTLS_HEADER_H_

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>

#include <common/def.h>

#include <openssl/curve25519.h>

////////// Message Types
#define CLTLS_MSG_TYPE_CLIENT_HELLO 0x00
#define CLTLS_MSG_TYPE_SERVER_HELLO 0x01
#define CLTLS_MSG_TYPE_SERVER_PUBKEY 0x10
#define CLTLS_MSG_TYPE_SERVER_PUBKEY_VERIFY 0x11
#define CLTLS_MSG_TYPE_SERVER_PUBKEY_REQUEST 0x12
#define CLTLS_MSG_TYPE_SERVER_HANDSHAKE_FINISHED 0x13
#define CLTLS_MSG_TYPE_CLIENT_PUBKEY 0x20
#define CLTLS_MSG_TYPE_CLIENT_PUBKEY_VERIFY 0x21
#define CLTLS_MSG_TYPE_CLIENT_HANDSHAKE_FINISHED 0x22
#define CLTLS_MSG_TYPE_HANDSHAKE_SUCCEED 0x90
#define CLTLS_MSG_TYPE_APPLICATION_DATA 0xA0
#define CLTLS_MSG_TYPE_ERROR_STOP_NOTIFY 0xF0

////////// Cipher Suites
// Key Negotiation and Digital Signature schemes are fixed
// in CL-TLS(X25519 and ED25519);
// only Encryption and Hash schemes can be specified
#define CLTLS_CIPHER_NONE 0x00
#define CLTLS_CIPHER_ASCON128A_ASCONHASHA 0x10
#define CLTLS_CIPHER_ASCON128A_SHA256 0x11
#define CLTLS_CIPHER_AES128GCM_ASCONHASHA 0x20
#define CLTLS_CIPHER_AES128GCM_SHA256 0x21

////////// Application Layer Protocols
// MQTT protocol
#define CLTLS_PROTOCOL_MQTT 0x00
// For communications with KGC.
// When message type is KGC_REGISTER_REQUEST,
// client pubkey is not requested.
#define CLTLS_PROTOCOL_KGC 0x10
#define CLTLS_PROTOCOL_KGC_REGISTER_REQUEST 0x11

////////// Error Codes
#define CLTLS_ERROR_INTERNAL_EXECUTION_ERROR 0x10
#define CLTLS_ERROR_UNEXPECTED_MSG_TYPE 0x11
#define CLTLS_ERROR_INVALID_APPLICATION_LAYER_PROTOCOL 0x12
#define CLTLS_ERROR_IDENTITY_NOT_PERMITTED 0x13
#define CLTLS_ERROR_NO_SUPPORTED_CIPHER_SUITE 0x14
#define CLTLS_ERROR_INVALID_PUBLIC_KEY_LENGTH 0x15
#define CLTLS_ERROR_PUBLIC_KEY_VERIFY_FAILED 0x16
#define CLTLS_ERROR_INVALID_TRAFFIC_SIGNATURE_LENGTH 0x17
#define CLTLS_ERROR_TRAFFIC_SIGNATURE_VERIFY_FAILED 0x18
#define CLTLS_ERROR_INVALID_VERIFY_DATA_LENGTH 0x19
#define CLTLS_ERROR_VERIFY_DATA_VERIFY_FAILED 0x1A
#define CLTLS_ERROR_SELECTED_CIPHER_SUITE_UNSUPPORTED 0x1B
#define CLTLS_ERROR_APPLICATION_LAYER_ERROR 0x20

////////// Helper Macros
#define CLTLS_COMMON_HEADER_LENGTH 5
#define CLTLS_MSG_TYPE(H) ((H)[0])
#define CLTLS_REMAINING_LENGTH(H) (ntohl(*(uint32_t *)((H) + 1)))
#define CLTLS_REMAINING_HEADER(H) ((H) + CLTLS_COMMON_HEADER_LENGTH)
#define CLTLS_SET_COMMON_HEADER(H, MT, RL)  \
    do                                      \
    {                                       \
        (H)[0] = (MT);                      \
        *(uint32_t *)((H) + 1) = htonl(RL); \
    } while (false)

#define CLTLS_SIGNATURE_LENGTH \
    (ED25519_SIGNATURE_LEN +   \
     ED25519_SIGNATURE_LEN)

#define CLTLS_APPLICATION_LAYER_PROTOCOL_LENGTH 1
#define CLTLS_ENTITY_PKA_LENGTH ED25519_PUBLIC_KEY_LEN
#define CLTLS_ENTITY_PKB_LENGTH ED25519_PUBLIC_KEY_LEN
#define CLTLS_ENTITY_ID_PKAB_SIGNATURE_LENGTH CLTLS_SIGNATURE_LENGTH
#define CLTLS_ENTITY_PUBLIC_KEY_LENGTH \
    (CLTLS_ENTITY_PKA_LENGTH +         \
     CLTLS_ENTITY_PKB_LENGTH +         \
     CLTLS_ENTITY_ID_PKAB_SIGNATURE_LENGTH)
#define CLTLS_ENTITY_SKA_LENGTH ED25519_PRIVATE_KEY_LEN
#define CLTLS_ENTITY_SKB_LENGTH ED25519_PRIVATE_KEY_LEN
#define CLTLS_ENTITY_PRIVATE_KEY_LENGTH \
    (CLTLS_ENTITY_SKA_LENGTH + CLTLS_ENTITY_SKB_LENGTH)
#define CLTLS_ID_PKAB_LENGTH   \
    (ENTITY_IDENTITY_LENGTH +  \
     CLTLS_ENTITY_PKA_LENGTH + \
     CLTLS_ENTITY_PKB_LENGTH)
#define CLTLS_KE_PUBLIC_KEY_LENGTH X25519_PUBLIC_VALUE_LEN
#define CLTLS_KE_PRIVATE_KEY_LENGTH X25519_PRIVATE_KEY_LEN
#define CLTLS_HANDSHAKE_RANDOM_LENGTH 32
#define CLTLS_TRAFFIC_SIGNATURE_LENGTH CLTLS_SIGNATURE_LENGTH
#define CLTLS_CIPHER_SUITE_COUNT_LENGTH 1
#define CLTLS_CIPHER_SUITE_LENGTH 1
#define CLTLS_ERROR_CODE_LENGTH 1

/******************************************************
 * Client Hello
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length                    |  4B
 * ---------------------------------------
 * | Application Layer Protocol          |  1B
 * ---------------------------------------
 * | Client Identity                     |  8B
 * ---------------------------------------
 * | Cipher Suite Count                  |  1B
 * ---------------------------------------
 * | Cipher Suites                       |  (1*Count)B
 * ---------------------------------------
 * | Client KE Public Key                |  32B
 * ---------------------------------------
 * | Client Handshake Random             |  32B
 * ---------------------------------------
 *
 ******************************************************/

/******************************************************
 * Server Hello
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length                    |  4B
 * ---------------------------------------
 * | Selected Cipher Suite               |  1B
 * ---------------------------------------
 * | Server KE Public Key                |  32B
 * ---------------------------------------
 * | Server Handshake Random             |  32B
 * ---------------------------------------
 *
 ******************************************************/
#define CLTLS_SERVER_HELLO_HEADER_LENGTH \
    (CLTLS_COMMON_HEADER_LENGTH +        \
     CLTLS_CIPHER_SUITE_LENGTH +         \
     CLTLS_KE_PUBLIC_KEY_LENGTH +        \
     CLTLS_HANDSHAKE_RANDOM_LENGTH)

/******************************************************
 * Server Public Key
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length                    |  4B
 * ---------------------------------------
 * | |------------------------------|    | (Encrypted)
 * | | Server Public Key            |    |
 * | |------------------------------|    |
 * ---------------------------------------
 *
 ******************************************************/

/******************************************************
 * Server Public Key Verify
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length                    |  4B
 * ---------------------------------------
 * | |------------------------------|    | (Encrypted)
 * | | Traffic Signature            | 64B|
 * | |------------------------------|    |
 * ---------------------------------------
 *
 ******************************************************/

/******************************************************
 * Server Public Key Request
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length(0)                 |  4B
 * ---------------------------------------
 *
 ******************************************************/
#define CLTLS_SERVER_PUBKEY_REQUEST_HEADER_LENGTH CLTLS_COMMON_HEADER_LENGTH

/******************************************************
 * Server Handshake Finished
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length                    |  4B
 * ---------------------------------------
 * | |------------------------------|    | (Encrypted)
 * | | Traffic HMAC Verify Data     |    |
 * | |------------------------------|    |
 * ---------------------------------------
 *
 ******************************************************/

/******************************************************
 * Client Public Key
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length                    |  4B
 * ---------------------------------------
 * | |------------------------------|    | (Encrypted)
 * | | Client Public Key            |    |
 * | |------------------------------|    |
 * ---------------------------------------
 *
 ******************************************************/

/******************************************************
 * Client Public Key Verify
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length                    |  4B
 * ---------------------------------------
 * | |------------------------------|    | (Encrypted)
 * | | Traffic Signature            | 64B|
 * | |------------------------------|    |
 * ---------------------------------------
 *
 ******************************************************/

/******************************************************
 * Client Handshake Finished
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length                    |  4B
 * ---------------------------------------
 * | |------------------------------|    | (Encrypted)
 * | | Traffic HMAC Verify Data     |    |
 * | |------------------------------|    |
 * ---------------------------------------
 *
 ******************************************************/

/******************************************************
 * Handshake Succeed
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length(0)                 |  4B
 * ---------------------------------------
 *
 ******************************************************/

/******************************************************
 * Application Data
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length                    |  4B
 * ---------------------------------------
 * | |------------------------------|    | (Encrypted)
 * | | Application Data             |    |
 * | |------------------------------|    |
 * ---------------------------------------
 *
 ******************************************************/

/******************************************************
 * Error Stop Notify
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length(1)                 |  4B
 * ---------------------------------------
 * | Error Code                          |  1B
 * ---------------------------------------
 *
 ******************************************************/
#define CLTLS_ERROR_STOP_NOTIFY_HEADER_LENGTH \
    (CLTLS_COMMON_HEADER_LENGTH +             \
     CLTLS_ERROR_CODE_LENGTH)

#define CLTLS_SEND_ERROR_STOP_NOTIFY(FD, ERROR_CODE)              \
    do                                                            \
    {                                                             \
        uint8_t error_stop_notify_send_data                       \
            [CLTLS_ERROR_STOP_NOTIFY_HEADER_LENGTH] = {0};        \
        CLTLS_SET_COMMON_HEADER(error_stop_notify_send_data,      \
                                CLTLS_MSG_TYPE_ERROR_STOP_NOTIFY, \
                                CLTLS_ERROR_CODE_LENGTH);         \
        CLTLS_REMAINING_HEADER(error_stop_notify_send_data)       \
        [0] = ERROR_CODE;                                         \
        TcpSend(FD,                                               \
                error_stop_notify_send_data,                      \
                CLTLS_ERROR_STOP_NOTIFY_HEADER_LENGTH);           \
    } while (false)

const char *GetCltlsErrorMessage(const uint8_t error_code);
void BindIdPkaPkb(const uint8_t *identity,
                  const uint8_t *pka,
                  const uint8_t *pkb, uint8_t *out);
int CltlsSign(uint8_t *out,
              const uint8_t *message,
              const size_t message_len,
              const uint8_t *private_key);
int CltlsVerify(const uint8_t *message,
                const size_t message_len,
                const uint8_t *signature,
                const uint8_t *public_key);
inline bool ShouldRequestClientPublicKey(const uint8_t application_layer_protocol)
{
    return application_layer_protocol != CLTLS_PROTOCOL_KGC_REGISTER_REQUEST;
}

#endif