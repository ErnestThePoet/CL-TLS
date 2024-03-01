#ifndef CLIENT_TCP_REQUEST_HANDLER_H_
#define CLIENT_TCP_REQUEST_HANDLER_H_

#include <protocol/cltls/client_handshake.h>
#include <protocol/cltls/application.h>

#include <protocol/connctl/connctl_header.h>
#include <protocol/mqtt/mqtt_header.h>

#include "client_args.h"
#include "client_globals.h"

#define CLIENT_CLOSE_C_FREE_RETURN       \
    do                                   \
    {                                    \
        TcpClose(ctx->client_socket_fd); \
        ByteVecFree(&buffer);            \
        free(arg);                       \
        return NULL;                     \
    } while (false)

#define CLIENT_CLOSE_CS_FREE_RETURN \
    do                              \
    {                               \
        TcpClose(server_socket_fd); \
        CLIENT_CLOSE_C_FREE_RETURN; \
    } while (false)

#define CLIENT_SEND_CONNECT_FAILURE                                     \
    do                                                                  \
    {                                                                   \
        ByteVecResize(&buffer, CONNCTL_CONNECT_RESPONSE_HEADER_LENGTH); \
        buffer.data[0] = CONNCTL_MSG_TYPE_CONNECT_RESPONSE;             \
        buffer.data[CONNCTL_MSG_TYPE_LENGTH] =                          \
            CONNCTL_CONNECT_STATUS_FAILURE;                             \
        TcpSend(ctx->client_socket_fd,                                  \
                buffer.data,                                            \
                CONNCTL_CONNECT_RESPONSE_HEADER_LENGTH);                \
    } while (false)

#define CLIENT_SEND_CONNECT_FAILURE_CONTINUE \
    CLIENT_SEND_CONNECT_FAILURE;             \
    continue

#define CLIENT_SEND_CONNECT_FAILURE_CLOSE_S_CONTINUE \
    CLIENT_SEND_CONNECT_FAILURE;                     \
    TcpClose(server_socket_fd);                      \
    continue

#define CLIENT_SEND_ERROR_STOP_NOTIFY_SEND_CONNECT_FAILURE_CLOSE_S_CONTINUE(ERROR_CODE) \
    CLTLS_SEND_ERROR_STOP_NOTIFY(server_socket_fd, ERROR_CODE);                         \
    CLIENT_SEND_CONNECT_FAILURE_CLOSE_S_CONTINUE

#define CLIENT_SEND_ERROR_STOP_NOTIFY_CLOSE_CS_FREE_RETURN(ERROR_CODE) \
    do                                                                 \
    {                                                                  \
        CLTLS_SEND_ERROR_STOP_NOTIFY(server_socket_fd, ERROR_CODE);    \
        CLIENT_CLOSE_CS_FREE_RETURN;                                   \
    } while (false)

void *ClientTcpRequestHandler(void *arg);

#endif