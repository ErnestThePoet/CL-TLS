#ifndef PARSE_SERVER_ARGS_H_
#define PARSE_SERVER_ARGS_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <common/def.h>

#include <argparse/argparse.h>

#include "server_args.h"

bool ParseServerArgs(
    const int argc, char *argv[], ServerArgs *server_args_ret);

#endif