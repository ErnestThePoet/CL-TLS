#ifndef CLTLS_HEADER_H_
#define CLTLS_HEADER_H_

#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

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
#define CLTLS_MSG_TYPE_APPLICATION_DATA 0xA0
#define CLTLS_MSG_TYPE_CLOSE_CONNECTION 0xB0
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
// When KGC message type is REGISTER_REQUEST,
// client pubkey is not requested.
#define CLTLS_PROTOCOL_KGC 0x10

////////// Error Codes
#define CLTLS_ERROR_INTERNAL_EXECUTION_ERROR 0x10
#define CLTLS_ERROR_UNEXPECTED_MSG_TYPE 0x11
#define CLTLS_ERROR_IDENTITY_NOT_PERMITTED 0x12
#define CLTLS_ERROR_NO_SUPPORTED_CIPHER_SUITE 0x13

////////// Helper Macros
#define CLTLS_COMMON_HEADER_LENGTH 3
#define CLTLS_MSG_TYPE(H) ((H)[0])
#define CLTLS_REMAINING_LENGTH(H) (ntohs(*(uint16_t *)((H) + 1)))
#define CLTLS_REMAINING_HEADER(H) ((H) + CLTLS_COMMON_HEADER_LENGTH)
#define CLTLS_SET_COMMON_HEADER(H, MT, RL)  \
    do                                      \
    {                                       \
        (H)[0] = (MT);                      \
        *(uint16_t *)((H) + 1) = htons(RL); \
    } while (false)

#define CLTLS_APPLICATION_LAYER_PROTOCOL_LENGTH 1
#define CLTLS_IDENTITY_LENGTH 32
#define CLTLS_ENTITY_PUBLIC_KEY_KEY_LENGTH ED25519_PUBLIC_KEY_LEN
#define CLTLS_ENTITY_PUBLIC_KEY_SIGNATURE_LENGTH ED25519_SIGNATURE_LEN
#define CLTLS_ENTITY_PUBLIC_KEY_LENGTH \
    (CLTLS_ENTITY_PUBLIC_KEY_KEY_LENGTH + CLTLS_ENTITY_PUBLIC_KEY_SIGNATURE_LENGTH)
#define CLTLS_ENTITY_PRIVATE_KEY_LENGTH ED25519_PRIVATE_KEY_LEN
#define CLTLS_KE_PUBLIC_KEY_LENGTH X25519_PUBLIC_VALUE_LEN
#define CLTLS_KE_PRIVATE_KEY_LENGTH X25519_PRIVATE_KEY_LEN
#define CLTLS_KE_RANDOM_LENGTH 32
#define CLTLS_TRAFFIC_SIGNATURE_LENGTH ED25519_SIGNATURE_LEN
#define CLTLS_CIPHER_SUITE_COUNT_LENGTH 1
#define CLTLS_CIPHER_SUITE_LENGTH 1
#define CLTLS_ERROR_CODE_LENGTH 1

/******************************************************
 * Client Hello
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length                    |  2B
 * ---------------------------------------
 * | Application Layer Protocol          |  1B
 * ---------------------------------------
 * | Client Identity                     |  32B
 * ---------------------------------------
 * | Cipher Suite Count                  |  1B
 * ---------------------------------------
 * | Cipher Suites                       |  (1*Count)B
 * ---------------------------------------
 * | Client KE Public Key                |  32B
 * ---------------------------------------
 * | Client KE Random                    |  32B
 * ---------------------------------------
 *
 ******************************************************/

/******************************************************
 * Server Hello
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length                    |  2B
 * ---------------------------------------
 * | Selected Cipher Suite               |  1B
 * ---------------------------------------
 * | Server KE Public Key                |  32B
 * ---------------------------------------
 * | Server KE Random                    |  32B
 * ---------------------------------------
 *
 ******************************************************/
#define CLTLS_SERVER_HELLO_HEADER_LENGTH \
    (CLTLS_COMMON_HEADER_LENGTH +        \
     CLTLS_CIPHER_SUITE_LENGTH +         \
     CLTLS_KE_PUBLIC_KEY_LENGTH +        \
     CLTLS_KE_RANDOM_LENGTH)

/******************************************************
 * Server Public Key
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length                    |  2B
 * ---------------------------------------
 * | |------------------------------|    | (Encrypted)
 * | | Server Public Key            | 32B|
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
 * | Remaining Length                    |  2B
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
 * | Remaining Length(0)                 |  2B
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
 * | Remaining Length                    |  2B
 * ---------------------------------------
 * | |------------------------------|    | (Encrypted)
 * | | Traffic Hash                 |    |
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
 * | Remaining Length                    |  2B
 * ---------------------------------------
 * | |------------------------------|    | (Encrypted)
 * | | Traffic Hash                 |    |
 * | |------------------------------|    |
 * ---------------------------------------
 *
 ******************************************************/

/******************************************************
 * Application Data
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length                    |  2B
 * ---------------------------------------
 * | |------------------------------|    | (Encrypted)
 * | | Application Data             |    |
 * | |------------------------------|    |
 * ---------------------------------------
 *
 ******************************************************/

/******************************************************
 * Close Connection
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length(0)                 |  2B
 * ---------------------------------------
 *
 ******************************************************/
#define CLTLS_CLOSE_CONNECTION_HEADER_LENGTH CLTLS_COMMON_HEADER_LENGTH

/******************************************************
 * Error Stop Notify
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length(1)                 |  2B
 * ---------------------------------------
 * | Error Code                          |  1B
 * ---------------------------------------
 *
 ******************************************************/
#define CLTLS_ERROR_STOP_NOTIFY_HEADER_LENGTH \
    (CLTLS_COMMON_HEADER_LENGTH +             \
     CLTLS_ERROR_CODE_LENGTH)

const char *GetCltlsErrorMessage(const uint8_t error_code);

#endif