#ifndef SERVER_TCP_REQUEST_HANDLER_H_
#define SERVER_TCP_REQUEST_HANDLER_H_

#include <protocol/cltls/client_handshake.h>
#include <protocol/cltls/server_handshake.h>
#include <protocol/cltls/application.h>

#include <protocol/kgc/kgc_header.h>

#include "server_args.h"
#include "server_globals.h"

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

#define KGC_SERVE_BS_SEND_ERROR_STOP_NOTIFY_CLOSE_SEND_FAILURE(ERROR_CODE)    \
    do                                                                        \
    {                                                                         \
        CLTLS_SEND_ERROR_STOP_NOTIFY(belonging_server_socket_fd, ERROR_CODE); \
        KGC_SERVE_BS_CLOSE_SEND_FAILURE;                                      \
    } while (false)

void *ServerTcpRequestHandler(void *arg);

#endif