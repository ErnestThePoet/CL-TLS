#ifndef HANDSHAKER_H_
#define HANDSHAKER_H_

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <common/def.h>
#include <util/log.h>
#include <util/byte_vec.h>
#include <util/util.h>
#include <socket/tcp/tcp.h>

#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/curve25519.h>
#include <openssl/hmac.h>
#include <openssl/hkdf.h>
#include <crypto_wrapper/crypto_wrapper.h>
#include <crypto_wrapper/get_schemes.h>

#include <database/idip.h>
#include <database/permitted_ids.h>

#include "cltls_header.h"

typedef struct
{
    uint8_t cipher_suite;
} CipherSuite;
#define P
#define T CipherSuite
#include <set.h>

typedef struct
{
    AeadScheme *aead;
    uint8_t client_key[MAX_ENC_KEY_LENGTH];
    uint8_t server_key[MAX_ENC_KEY_LENGTH];
    uint8_t client_npub_iv[MAX_NPUB_IV_LENGTH];
    uint8_t server_npub_iv[MAX_NPUB_IV_LENGTH];
} HandshakeResult;

// Error handling principles:
// - When memory allocation fails, exit with EXIT_FAILURE immediately.
// - When TcpSend() or TcpRecv() fails, free buffers and return.
// - In other cases, send an ERROR_STOP_NOTIFY then free buffers and return.

#define CLOSE_FREE_RETURN                \
    do                                   \
    {                                    \
        TcpClose(ctx->socket_fd);        \
        ByteVecFree(&receive_buffer);    \
        ByteVecFree(&send_buffer);       \
        ByteVecFree(&traffic_buffer);    \
        ByteVecFree(&decryption_buffer); \
        return false;                    \
    } while (false)

#define CHECK_ERROR_STOP_NOTIFY                                                      \
    do                                                                               \
    {                                                                                \
        if (CLTLS_MSG_TYPE(receive_buffer.data) == CLTLS_MSG_TYPE_ERROR_STOP_NOTIFY) \
        {                                                                            \
            LogError("[%s] The other party send ERROR_STOP_NOTIFY: %s",              \
                     current_stage,                                                  \
                     GetCltlsErrorMessage(                                           \
                         CLTLS_REMAINING_HEADER(receive_buffer.data[0])));           \
            CLOSE_FREE_RETURN;                                                       \
        }                                                                            \
    } while (false)

#define SEND_ERROR_STOP_NOTIFY(ERROR_CODE)                        \
    do                                                            \
    {                                                             \
        uint8_t error_stop_notify_send_data                       \
            [CLTLS_ERROR_STOP_NOTIFY_HEADER_LENGTH] = {0};        \
        CLTLS_SET_COMMON_HEADER(error_stop_notify_send_data,      \
                                CLTLS_MSG_TYPE_ERROR_STOP_NOTIFY, \
                                2);                               \
        error_stop_notify_send_data[3] = ERROR_CODE;              \
        TcpSend(ctx->socket_fd,                                   \
                error_stop_notify_send_data,                      \
                CLTLS_ERROR_STOP_NOTIFY_HEADER_LENGTH);           \
        CLOSE_FREE_RETURN;                                        \
    } while (false)

#define HANDSHAKE_RECEIVE(MSG_TYPE, APPEND_TRAFFIC)                                  \
    do                                                                               \
    {                                                                                \
        ByteVecResize(&receive_buffer, CLTLS_COMMON_HEADER_LENGTH);                  \
                                                                                     \
        if (!TcpRecv(ctx->socket_fd,                                                 \
                     receive_buffer.data,                                            \
                     CLTLS_COMMON_HEADER_LENGTH))                                    \
        {                                                                            \
            LogError("[%s] Failed to receive common header of " #MSG_TYPE,           \
                     current_stage);                                                 \
            CLOSE_FREE_RETURN;                                                       \
        }                                                                            \
                                                                                     \
        if (CLTLS_MSG_TYPE(receive_buffer.data) != CLTLS_MSG_TYPE_##MSG_TYPE &&      \
            CLTLS_MSG_TYPE(receive_buffer.data) != CLTLS_MSG_TYPE_ERROR_STOP_NOTIFY) \
        {                                                                            \
            LogError("[%s] Invalid message type received, expecting " #MSG_TYPE,     \
                     current_stage);                                                 \
            SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_UNEXPECTED_MSG_TYPE);                 \
        }                                                                            \
                                                                                     \
        receive_remaining_length = CLTLS_REMAINING_LENGTH(receive_buffer.data);      \
                                                                                     \
        ByteVecResizeBy(&receive_buffer, receive_remaining_length);                  \
                                                                                     \
        if (!TcpRecv(ctx->socket_fd,                                                 \
                     CLTLS_REMAINING_HEADER(receive_buffer.data),                    \
                     receive_remaining_length))                                      \
        {                                                                            \
            LogError("[%s] Failed to receive remaining part of " #MSG_TYPE,          \
                     current_stage);                                                 \
            CLOSE_FREE_RETURN;                                                       \
        }                                                                            \
                                                                                     \
        CHECK_ERROR_STOP_NOTIFY;                                                     \
                                                                                     \
        if (APPEND_TRAFFIC)                                                          \
        {                                                                            \
            ByteVecPushBackBlockFromByteVec(&traffic_buffer, &receive_buffer);       \
        }                                                                            \
    } while (false)

#define CALCULATE_HANDSHAKE_KEY                                                      \
    do                                                                               \
    {                                                                                \
        memcpy(secret_info, "derived", 7);                                           \
        hash->Hash("", 0, secret_info + 7);                                          \
                                                                                     \
        if (!HKDF(derived_secret, hash->hash_size,                                   \
                  md_hmac_hkdf,                                                      \
                  early_secret_secret_salt, hash->hash_size,                         \
                  early_secret_secret_salt, hash->hash_size,                         \
                  secret_info, hash->hash_size + 7))                                 \
        {                                                                            \
            LogError("[%s] HKDF() for |derived_secret| failed: %s",                  \
                     current_stage,                                                  \
                     ERR_error_string(ERR_get_error(), NULL));                       \
            SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);            \
        }                                                                            \
                                                                                     \
        if (!HKDF_extract(handshake_secret, &hkdf_extract_out_length,                \
                          md_hmac_hkdf,                                              \
                          shared_secret, X25519_SHARED_KEY_LEN,                      \
                          derived_secret, hash->hash_size))                          \
        {                                                                            \
            LogError("[%s] HKDF_extract() for |handshake_secret| failed: %s",        \
                     current_stage,                                                  \
                     ERR_error_string(ERR_get_error(), NULL));                       \
            SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);            \
        }                                                                            \
                                                                                     \
        hash->Hash(traffic_buffer.data, traffic_buffer.size, secret_info + 12);      \
        memcpy(secret_info, "c hs traffic", 12);                                     \
                                                                                     \
        if (!HKDF_expand(client_secret, hash->hash_size,                             \
                         md_hmac_hkdf,                                               \
                         handshake_secret, hash->hash_size,                          \
                         secret_info, hash->hash_size + 12))                         \
        {                                                                            \
            LogError("[%s] HKDF_expand() for |client_secret| failed: %s",            \
                     current_stage,                                                  \
                     ERR_error_string(ERR_get_error(), NULL));                       \
            SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);            \
        }                                                                            \
                                                                                     \
        memcpy(secret_info, "s hs traffic", 12);                                     \
                                                                                     \
        if (!HKDF_expand(server_secret, hash->hash_size,                             \
                         md_hmac_hkdf,                                               \
                         handshake_secret, hash->hash_size,                          \
                         secret_info, hash->hash_size + 12))                         \
        {                                                                            \
            LogError("[%s] HKDF_expand() for |server_secret| failed: %s",            \
                     current_stage,                                                  \
                     ERR_error_string(ERR_get_error(), NULL));                       \
            SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);            \
        }                                                                            \
                                                                                     \
        if (!HKDF_expand(client_handshake_key, aead->key_size,                       \
                         md_hmac_hkdf,                                               \
                         client_secret, hash->hash_size,                             \
                         "key", 3))                                                  \
        {                                                                            \
            LogError("[%s] HKDF_expand() for |client_handshake_key| failed: %s",     \
                     current_stage,                                                  \
                     ERR_error_string(ERR_get_error(), NULL));                       \
            SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);            \
        }                                                                            \
                                                                                     \
        if (!HKDF_expand(server_handshake_key, aead->key_size,                       \
                         md_hmac_hkdf,                                               \
                         server_secret, hash->hash_size,                             \
                         "key", 3))                                                  \
        {                                                                            \
            LogError("[%s] HKDF_expand() for |server_handshake_key| failed: %s",     \
                     current_stage,                                                  \
                     ERR_error_string(ERR_get_error(), NULL));                       \
            SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);            \
        }                                                                            \
                                                                                     \
        if (!HKDF_expand(client_handshake_npub_iv, aead->npub_iv_size,               \
                         md_hmac_hkdf,                                               \
                         client_secret, hash->hash_size,                             \
                         "iv", 2))                                                   \
        {                                                                            \
            LogError("[%s] HKDF_expand() for |client_handshake_npub_iv| failed: %s", \
                     current_stage,                                                  \
                     ERR_error_string(ERR_get_error(), NULL));                       \
            SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);            \
        }                                                                            \
                                                                                     \
        if (!HKDF_expand(server_handshake_npub_iv, aead->npub_iv_size,               \
                         md_hmac_hkdf,                                               \
                         server_secret, hash->hash_size,                             \
                         "iv", 2))                                                   \
        {                                                                            \
            LogError("[%s] HKDF_expand() for |server_handshake_npub_iv| failed: %s", \
                     current_stage,                                                  \
                     ERR_error_string(ERR_get_error(), NULL));                       \
            SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);            \
        }                                                                            \
    } while (false)

#endif