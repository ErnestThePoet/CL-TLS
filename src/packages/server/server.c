#include <stdio.h>
#include <stdlib.h>

#include <common/def.h>
#include <socket/tcp/tcp.h>

#include "server_args.h"
#include "parse_server_args.h"
#include "server_tcp_request_handler.h"

void PrintUsage()
{
    const char *kUsageHint = "Usage:\n"
                             "cltls_server -pkg|-proxy --port <listen-port> [OPTION]...\n"
                             "Where possible OPTIONS are:\n"
                             "--forward <ip>:<port>      Set proxy pass destination,\n"
                             "                           required in PROXY mode\n"
                             "--log <ERROR|WARN|INFO>    Set log level, defaults to WARN\n"
                             "Use 'cltls_server --help' to show this summary\n";

    fputs(kUsageHint, stderr);
}

int main(int argc, char *argv[])
{
    ServerArgs server_args;
    if (!ParseServerArgs(argc, argv, &server_args))
    {
        PrintUsage();
        return FAILURE;
    }

    int server_socket_fd = 0;
    if (!TcpCreateServer(server_args.listen_port, &server_socket_fd))
    {
        return FAILURE;
    }

    TcpRunServer(server_socket_fd, ServerTcpRequestHandler, &server_args);

    return SUCCESS;
}
