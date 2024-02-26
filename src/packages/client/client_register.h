#ifndef CLIENT_REGISTER_H_
#define CLIENT_REGISTER_H_

#include <protocol/cltls/client_handshake.h>
#include <protocol/cltls/application.h>

#include <protocol/kgc/kgc_header.h>

#include "client_args.h"
#include "client_globals.h"

#define CLIENT_REGISTER_FREE_RETURN_FALSE \
    do                                    \
    {                                     \
        ByteVecFree(&send_buffer);        \
        ByteVecFree(&receive_buffer);     \
        return false;                     \
    } while (false)

#define CLIENT_REGISTER_CLOSE_FREE_RETURN_FALSE \
    do                                          \
    {                                           \
        TcpClose(kgc_socket_fd);                \
        CLIENT_REGISTER_FREE_RETURN_FALSE;      \
    } while (false)

bool ClientRegister(const char *belonging_servers_file_path);

#endif