#ifndef SERVER_TCP_REQUEST_HANDLER_H_
#define SERVER_TCP_REQUEST_HANDLER_H_

#include <protocol/cltls/client_handshake.h>
#include <protocol/cltls/server_handshake.h>
#include <protocol/cltls/application.h>

#include <protocol/kgc/kgc_header.h>
#include <protocol/connctl/connctl_header.h>
#include <protocol/mqtt/mqtt_header.h>

#include "server_args.h"
#include "server_globals.h"

#define SERVER_CLOSE_FREE_RETURN         \
    do                                   \
    {                                    \
        TcpClose(ctx->client_socket_fd); \
        free(arg);                       \
        return NULL;                     \
    } while (false)

#define KGC_SERVE_FREE_RETURN_FALSE   \
    do                                \
    {                                 \
        ByteVecFree(&send_buffer);    \
        ByteVecFree(&receive_buffer); \
        return false;                 \
    } while (false)

#define KGC_SERVE_SEND_REGISTER_RESPONSE_FAILURE                    \
    do                                                              \
    {                                                               \
        ByteVecResize(&send_buffer,                                 \
                      KGC_REGISTER_RESPONSE_FAILURE_HEADER_LENGTH); \
        send_buffer.data[0] = KGC_MSG_TYPE_RESIGTER_RESPONSE;       \
        send_buffer.data[1] = KGC_REGISTER_STATUS_FAILURE;          \
        SendApplicationData(socket_fd,                              \
                            handshake_result,                       \
                            false,                                  \
                            &send_buffer);                          \
        KGC_SERVE_FREE_RETURN_FALSE;                                \
    } while (false)

#define KGC_SERVE_BS_CLOSE_SEND_FAILURE           \
    do                                            \
    {                                             \
        TcpClose(belonging_server_socket_fd);     \
        KGC_SERVE_SEND_REGISTER_RESPONSE_FAILURE; \
    } while (false)

#define ADD_CLIENT_SERVE_FREE_RETURN_FALSE \
    do                                     \
    {                                      \
        ByteVecFree(&send_buffer);         \
        ByteVecFree(&receive_buffer);      \
        return false;                      \
    } while (false)

#define ADD_CLIENT_SERVE_SEND_RESPONSE_FAILURE                  \
    do                                                          \
    {                                                           \
        ByteVecResize(&send_buffer,                             \
                      KGC_ADD_CLIENT_RESPONSE_HEADER_LENGTH);   \
        send_buffer.data[0] = KGC_MSG_TYPE_ADD_CLIENT_RESPONSE; \
        send_buffer.data[1] = KGC_ADD_CLIENT_STATUS_FAILURE;    \
        SendApplicationData(socket_fd,                          \
                            handshake_result,                   \
                            false,                              \
                            &send_buffer);                      \
        ADD_CLIENT_SERVE_FREE_RETURN_FALSE;                     \
    } while (false)

#define MQTT_PROXY_SERVE_FREE_RETURN_FALSE \
    do                                     \
    {                                      \
        ByteVecFree(&buffer);              \
        return false;                      \
    } while (false)

#define MQTT_PROXY_SERVE_CLOSE_FREE_RETURN_FALSE \
    do                                           \
    {                                            \
        TcpClose(forward_socket_fd);             \
        MQTT_PROXY_SERVE_FREE_RETURN_FALSE;      \
    } while (false)

#define MQTT_PROXY_SERVE_SEND_ERROR_STOP_NOTIFY_CLOSE_FREE_RETURN_FALSE(ERROR_CODE) \
    do                                                                              \
    {                                                                               \
        CLTLS_SEND_ERROR_STOP_NOTIFY(socket_fd, ERROR_CODE);                        \
        MQTT_PROXY_SERVE_CLOSE_FREE_RETURN_FALSE;                                   \
    } while (false)

void *ServerTcpRequestHandler(void *arg);

#endif