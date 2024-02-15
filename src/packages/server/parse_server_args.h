#ifndef PARSE_SERVER_ARGS_H_
#define PARSE_SERVER_ARGS_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <common/def.h>

#include <argparse/argparse.h>

#include <protocol/cltls/cltls_header.h>

#include "server_args.h"

#define PRINT_ERROR_REQUIRED_OPTION_NOT_PROVIDED(NAME)                \
    do                                                                \
    {                                                                 \
        fprintf(stderr,                                               \
                "error: required option %s is not provided\n", NAME); \
        argparse_help_cb_no_exit(&arg_parse, options);                \
        exit(EXIT_FAILURE);                                           \
    } while (false)

#define PRINT_ERROR_INVALID_OPTION_VALUE(D, VALUE, NAME)        \
    do                                                          \
    {                                                           \
        fprintf(stderr,                                         \
                "error: invalid value '" D "' for option %s\n", \
                VALUE, NAME);                                   \
        argparse_help_cb_no_exit(&arg_parse, options);          \
        exit(EXIT_FAILURE);                                     \
    } while (false)

void ParseServerArgs(
    const int argc, char *argv[], ServerArgs *server_args_ret);

#endif