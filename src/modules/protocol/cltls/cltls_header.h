#ifndef CLTLS_HEADER_H_
#define CLTLS_HEADER_H_

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
#define CLTLS_MSG_TYPE_ERROR_STOP_NOTIFY 0xF0

// Key Negotiation and Digital Signature schemes are fixed
// in CL-TLS(X25519 and ED25519);
// only Encryption and Hash schemes can be specified

#define CLTLS_CIPHER_ASCON128A_ASCONHASHA 0x00
#define CLTLS_CIPHER_ASCON128A_SHA256 0x01
#define CLTLS_CIPHER_AES128GCM_ASCONHASHA 0x10
#define CLTLS_CIPHER_AES128GCM_SHA256 0x11

// MQTT protocol
#define CLTLS_PROTOCOL_MQTT 0x00
// New user key generation request to PKG.
// When this protocol is used, steps
// CLIENT_PUBKEY, CLIENT_PUBKEY_VERIFY and CLIENT_HANDSHAKE_FINISHED
// are omitted.
#define CLTLS_PROTOCOL_KEYGEN 0x10

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

/******************************************************
 * Server Public Key
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length                    |  2B
 * ---------------------------------------
 * | |------------------------------|    | (Encrypted)
 * | | Server Public Key Length     | 2B |
 * | |------------------------------|    |
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
 * | Remaining Length                    |  2B
 * ---------------------------------------
 * | |------------------------------|    | (Encrypted)
 * | | Traffic Signature Length     | 2B |
 * | |------------------------------|    |
 * | | Traffic Signature            |    |
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

/******************************************************
 * Server Handshake Finished
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length                    |  2B
 * ---------------------------------------
 * | |------------------------------|    | (Encrypted)
 * | | Traffic Hash Length          | 2B |
 * | |------------------------------|    |
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
 * | | Traffic Hash Length          | 2B |
 * | |------------------------------|    |
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
 * Error Stop Notify
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Remaining Length(2)                 |  2B
 * ---------------------------------------
 * | Error Code                          |  2B
 * ---------------------------------------
 *
 ******************************************************/

#endif