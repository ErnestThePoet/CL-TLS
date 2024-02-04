#include <stdio.h>
#include <stdlib.h>

#include "server_args.h"
#include "parse_server_args.h"
#include "tcp_create_server.h"
#include "tcp_run_server.h"

#include "common/def.h"

void PrintUsage(){
    const char *kUsageHint = "Usage:\n"
                             "cltls_server --port <listen-port> --forward <forward-ip>:<forward-port> [OPTION]...\n"
                             "Where possible OPTIONS are:\n"
                             "--log <ERROR|WARN|INFO>    Set log level, defaults to WARN";

    fputs(kUsageHint, stderr);
}

int main(int argc, char *argv[])
{
    ServerArgs server_args;
    if (!ParseServerArgs(argc, argv, &server_args)){
        PrintUsage();
        exit(FAILURE);
    }

    return SUCCESS;
}

