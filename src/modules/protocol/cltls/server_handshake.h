#ifndef SERVER_HANDSHAKE_H_
#define SERVER_HANDSHAKE_H_

#include "handshake.h"

typedef enum
{
    SERVER_MODE_KGC,
    SERVER_MODE_PROXY
} ServerMode;

typedef struct
{
    int socket_fd;
    ServerMode mode;
    uint8_t *server_identity;
    uint8_t *server_public_key;
    uint8_t *server_private_key;
    uint8_t *kgc_public_key;
    set_CipherSuite *server_cipher_suite_set;
    set_Id *server_permitted_id_set;
    uint8_t preferred_cipher_suite;
} ServerHandshakeCtx;

bool ServerHandshake(const ServerHandshakeCtx *ctx,
                     HandshakeResult *handshake_result_ret,
                     uint8_t *client_identity_ret,
                     uint8_t *application_layer_protocol_ret);

#endif