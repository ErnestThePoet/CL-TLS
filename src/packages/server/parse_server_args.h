#ifndef PARSE_SERVER_ARGS_H_
#define PARSE_SERVER_ARGS_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <common/def.h>

#include "server_args.h"

typedef enum
{
    PARSE_STATE_EXPECT_OPTION_NAME,
    PARSE_STATE_EXPECT_OPTION_VALUE
} ParseState;

typedef enum
{
    OPTION_NAME_NONE,
    OPTION_NAME_PORT,
    OPTION_NAME_FORWARD,
    OPTION_NAME_LOG
} OptionName;

static const int kMandatoryOptionCount = 2;

bool ParseServerArgs(
    const int argc, char *argv[], ServerArgs *server_args_ret);

#endif