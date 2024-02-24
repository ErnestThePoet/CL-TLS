#ifndef CLIENT_ARGS_H_
#define CLIENT_ARGS_H_

#include <stdint.h>
#include <stdbool.h>

#include <common/def.h>

typedef struct
{
    bool register_client;
    uint16_t listen_port;
    char config_file_path[MAX_PATH_LENGTH];
} ClientArgs;

#endif