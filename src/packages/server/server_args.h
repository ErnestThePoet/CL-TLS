#ifndef SERVER_ARGS_H_
#define SERVER_ARGS_H_

#include <stdint.h>

#include <common/def.h>

#include <argparse/argparse.h>

typedef enum
{
    SERVER_MODE_KGC,
    SERVER_MODE_PROXY
} ServerMode;

typedef struct
{
    ServerMode mode;
    uint16_t listen_port;
    char forward_ip[50];
    uint16_t forward_port;
    LogLevel log_level;
} ServerArgs;

#endif