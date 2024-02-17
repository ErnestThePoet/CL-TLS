#ifndef SERVER_TCP_REQUEST_HANDLER_H_
#define SERVER_TCP_REQUEST_HANDLER_H_

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include <common/def.h>
#include <common/log.h>
#include <common/util.h>
#include <socket/tcp/tcp.h>
#include <protocol/cltls/cltls_header.h>

#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/curve25519.h>
#include <openssl/hmac.h>
#include <openssl/hkdf.h>
#include <crypto_wrapper/crypto_wrapper.h>
#include <crypto_wrapper/get_schemes.h>

#include "server_args.h"
#include "server_globals.h"

#define INITIAL_TRAFFIC_CAPACITY 200
#define MAX_HASH_LENGTH 64
#define MAX_ENC_KEY_LENGTH 32
#define MAX_NPUB_IV_LENGTH 16

#define CLOSE_FREE_ARG_RETURN            \
    do                                   \
    {                                    \
        TcpClose(ctx->client_socket_fd); \
        free(arg);                       \
        return NULL;                     \
    } while (false)

#define CLOSE_FREE_ARG_BUF_RETURN        \
    do                                   \
    {                                    \
        TcpClose(ctx->client_socket_fd); \
        free(arg);                       \
        free(receive_remaining);         \
        free(send_data);                 \
        free(traffic);                   \
        return NULL;                     \
    } while (false)

#define CHECK_ERROR_STOP_NOTIFY                                                        \
    do                                                                                 \
    {                                                                                  \
        if (CLTLS_MSG_TYPE(receive_common_header) == CLTLS_MSG_TYPE_ERROR_STOP_NOTIFY) \
        {                                                                              \
            LogError("The other party send ERROR_STOP_NOTIFY: %s",                     \
                     GetCltlsErrorMessage(receive_remaining[0]));                      \
            CLOSE_FREE_ARG_BUF_RETURN;                                                 \
        }                                                                              \
    } while (false)

#define SEND_ERROR_STOP_NOTIFY_RETURN(ERROR_CODE)                                         \
    do                                                                                    \
    {                                                                                     \
        uint8_t error_stop_notify_send_data[CLTLS_ERROR_STOP_NOTIFY_HEADER_LENGTH] = {0}; \
        CLTLS_SET_COMMON_HEADER(error_stop_notify_send_data,                              \
                                CLTLS_MSG_TYPE_ERROR_STOP_NOTIFY,                         \
                                2);                                                       \
        error_stop_notify_send_data[3] = ERROR_CODE;                                      \
        TcpSend(ctx->client_socket_fd,                                                    \
                error_stop_notify_send_data,                                              \
                CLTLS_ERROR_STOP_NOTIFY_HEADER_LENGTH);                                   \
        CLOSE_FREE_ARG_BUF_RETURN;                                                        \
    } while (false)

#define APPEND_TRAFFIC(D, S)                                          \
    do                                                                \
    {                                                                 \
        if (traffic_length + S > traffic_capacity)                    \
        {                                                             \
            traffic = realloc(traffic, traffic_capacity * 2);         \
            if (traffic == NULL)                                      \
            {                                                         \
                LogError("Memory reallocation for |traffic| failed"); \
                free(receive_remaining);                              \
                free(send_data);                                      \
                CLOSE_FREE_ARG_RETURN;                                \
            }                                                         \
            traffic_capacity *= 2;                                    \
        }                                                             \
        memcpy(traffic + traffic_length, D, S);                       \
        traffic_length += S;                                          \
    } while (false)

void *ServerTcpRequestHandler(void *arg);
uint8_t ChooseCipherSuite(const uint8_t cipher_suite_count,
                          const uint8_t *cipher_suites,
                          const uint8_t preferred_cipher_suite);

#endif