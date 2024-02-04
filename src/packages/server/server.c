#include <stdio.h>
#include <stdlib.h>

#include "server_args.h"
#include "parse_server_args.h"
#include "tcp_create_server.h"
#include "tcp_run_server.h"

#include "common/def.h"

void PrintUsage()
{
    const char *kUsageHint = "Usage:\n"
                             "cltls_server --port <listen-port> --forward <forward-ip>:<forward-port> [OPTION]...\n"
                             "Where possible OPTIONS are:\n"
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
        exit(FAILURE);
    }

    printf("%u %s %u %d\n", server_args.listen_port, server_args.forward_ip, server_args.forward_port, server_args.log_level);

    return SUCCESS;
}
