#include "parse_server_args.h"

bool ParseServerArgs(
    const int argc, char *argv[], ServerArgs *server_args_ret)
{
    if (argc <= 1)
    {
        fprintf(stderr, "ParseServerArgs() error: Too few command line arguments\n");
        return false;
    }

    if (!strcmp(argv[0], "--help"))
    {
        return false;
    }

    

    return true;
}