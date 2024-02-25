#include <stdio.h>
#include <stdlib.h>

#include <common/def.h>
#include <socket/tcp/tcp.h>

#include "server_args.h"
#include "server_globals.h"
#include "parse_server_args.h"
#include "server_register.h"
#include "server_tcp_request_handler.h"

int main(int argc, char *argv[])
{
    ServerArgs server_args;
    ParseServerArgs(argc, argv, &server_args);

    if (!InitializeGlobals(&server_args))
    {
        return EXIT_FAILURE;
    }

    if (server_args.register_server)
    {
        bool register_successful = ServerRegister();
        FreeGlobals();
        return register_successful ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    int server_socket_fd = 0;
    if (!TcpCreateServer(server_args.listen_port,
                         &server_socket_fd))
    {
        FreeGlobals();
        return EXIT_FAILURE;
    }

    TcpRunServer(server_socket_fd,
                 ServerTcpRequestHandler,
                 &server_args);

    FreeGlobals();
    return EXIT_SUCCESS;
}
