#ifndef SERVER_REGISTER_H_
#define SERVER_REGISTER_H_

#include <protocol/cltls/client_handshake.h>
#include <protocol/cltls/application.h>

#include <protocol/kgc/kgc_header.h>

#include "server_args.h"
#include "server_globals.h"

#define SERVER_REGISTER_FREE_RETURN_FALSE \
    do                                    \
    {                                     \
        ByteVecFree(&send_buffer);        \
        ByteVecFree(&receive_buffer);     \
        return false;                     \
    } while (false)

#define SERVER_REGISTER_CLOSE_FREE_RETURN_FALSE \
    do                                          \
    {                                           \
        TcpClose(kgc_socket_fd);                \
        SERVER_REGISTER_FREE_RETURN_FALSE;      \
    } while (false)

#define SERVER_REGISTER_SEND_ERROR_STOP_NOFITY(ERROR_CODE)       \
    do                                                           \
    {                                                            \
        CLTLS_SEND_ERROR_STOP_NOTIFY(kgc_socket_fd, ERROR_CODE); \
        SERVER_REGISTER_CLOSE_FREE_RETURN_FALSE;                 \
    } while (false)

bool ServerRegister();

#endif