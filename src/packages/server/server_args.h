#ifndef SERVER_ARGS_H_
#define SERVER_ARGS_H_

#include <stdint.h>
#include <stdbool.h>

#include <common/def.h>

#include <argparse/argparse.h>

#include <protocol/cltls/server_handshake.h>

typedef struct
{
    bool register_server;
    ServerMode mode;
    uint16_t listen_port;
    char forward_ip[IP_STR_LENGTH];
    uint16_t forward_port;
    uint8_t preferred_cipher_suite;
    char config_file_path[MAX_PATH_LENGTH];
} ServerArgs;

#endif