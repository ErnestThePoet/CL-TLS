#ifndef SERVER_HANDSHAKER_H_
#define SERVER_HANDSHAKER_H_

#include "handshaker.h"

typedef enum
{
    SERVER_MODE_KGC,
    SERVER_MODE_PROXY
} ServerMode;

typedef struct
{
    int client_socket_fd;
    ServerMode mode;
    char *forward_ip;
    uint16_t forward_port;
    uint8_t *server_identity;
    uint8_t *server_public_key;
    uint8_t *server_private_key;
    uint8_t *kgc_public_key;
    set_CipherSuite *server_cipher_suite_set;
    set_Id *server_permitted_id_set;
    uint8_t preferred_cipher_suite;
} ServerHandshakeCtx;

// Error handling principles:
// - When memory allocation fails, exit with EXIT_FAILURE immediately.
// - When TcpSend() or TcpRecv() fails, free buffers and return.
// - In other cases, send an ERROR_STOP_NOTIFY then free buffers and return.

#define CLOSE_FREE_RETURN                \
    do                                   \
    {                                    \
        TcpClose(ctx->client_socket_fd); \
        ByteVecFree(&receive_buffer);    \
        ByteVecFree(&send_buffer);       \
        ByteVecFree(&traffic_buffer);    \
        return false;                    \
    } while (false)

#define CHECK_ERROR_STOP_NOTIFY                                                      \
    do                                                                               \
    {                                                                                \
        if (CLTLS_MSG_TYPE(receive_buffer.data) == CLTLS_MSG_TYPE_ERROR_STOP_NOTIFY) \
        {                                                                            \
            LogError("The other party send ERROR_STOP_NOTIFY: %s",                   \
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
        TcpSend(ctx->client_socket_fd,                            \
                error_stop_notify_send_data,                      \
                CLTLS_ERROR_STOP_NOTIFY_HEADER_LENGTH);           \
        CLOSE_FREE_RETURN;                                        \
    } while (false)

bool ServerHandshake(const ServerHandshakeCtx *ctx,
                     HandshakeResult *handshake_result_ret);

#endif