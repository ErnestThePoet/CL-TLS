#ifndef CLIENT_HANDSHAKE_H_
#define CLIENT_HANDSHAKE_H_

#include "handshake.h"

typedef struct
{
    int socket_fd;
    uint8_t application_layer_protocol;
    uint8_t *server_identity;
    uint8_t *client_identity;
    uint8_t *client_public_key;
    uint8_t *client_private_key;
    uint8_t *kgc_public_key;
    set_CipherSuite *client_cipher_suite_set;
} ClientHandshakeCtx;

bool ServerHandshake(const ClientHandshakeCtx *ctx,
                     HandshakeResult *handshake_result_ret);

#endif