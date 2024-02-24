#ifndef PARSE_CLIENT_ARGS_H_
#define PARSE_CLIENT_ARGS_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <common/def.h>

#include <argparse/argparse.h>

#include <protocol/cltls/cltls_header.h>

#include "client_args.h"

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

void ParseClientArgs(
    const int argc, char *argv[], ClientArgs *client_args_ret);

#endif