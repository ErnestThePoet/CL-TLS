#include <stdio.h>
#include <stdlib.h>

#include <common/def.h>
#include <socket/tcp/tcp.h>

#include "client_args.h"
#include "client_globals.h"
#include "parse_client_args.h"
#include "client_register.h"
#include "client_tcp_request_handler.h"

int main(int argc, char *argv[])
{
    ClientArgs client_args;
    ParseClientArgs(argc, argv, &client_args);

    if (!InitializeGlobals(&client_args))
    {
        return EXIT_FAILURE;
    }

    if (client_args.register_client)
    {
        bool register_successful = ClientRegister(
            client_args.belonging_servers_file_path);
        FreeGlobals();
        return register_successful ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    int server_socket_fd = 0;
    if (!TcpCreateServer(client_args.listen_port,
                         &server_socket_fd))
    {
        FreeGlobals();
        return EXIT_FAILURE;
    }

    char id_hex[ENTITY_IDENTITY_HEX_STR_LENGTH] = {0};
    Bin2Hex(kClientIdentity, id_hex, ENTITY_IDENTITY_LENGTH);
    LogInfo("Client started on port %hu", client_args.listen_port);
    LogInfo("Client ID is %s", id_hex);

    TcpRunServer(server_socket_fd,
                 ClientTcpRequestHandler,
                 &client_args);

    FreeGlobals();
    return EXIT_SUCCESS;
}
