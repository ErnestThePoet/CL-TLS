#include "client_handshaker.h"

bool ServerHandshake(const ClientHandshakeCtx *ctx,
                     HandshakeResult *handshake_result_ret)
{
    ByteVec receive_buffer;
    ByteVec send_buffer;
    ByteVec traffic_buffer;
    ByteVec decryption_buffer;

    ByteVecInitWithCapacity(&receive_buffer, INITIAL_SOCKET_BUFFER_CAPACITY);
    ByteVecInitWithCapacity(&send_buffer, INITIAL_SOCKET_BUFFER_CAPACITY);
    ByteVecInitWithCapacity(&traffic_buffer, INITIAL_TRAFFIC_BUFFER_CAPACITY);
    ByteVecInitWithCapacity(&decryption_buffer, INITIAL_SOCKET_BUFFER_CAPACITY);

    size_t receive_remaining_length = 0;

    // [Send] Client Hello
    const char *current_stage = "SEND Client Hello";

    uint8_t client_ke_pubkey[CLTLS_KE_PUBLIC_KEY_LENGTH] = {0};
    uint8_t client_ke_privkey[CLTLS_KE_PRIVATE_KEY_LENGTH] = {0};
    uint8_t client_ke_random[CLTLS_KE_RANDOM_LENGTH] = {0};
    X25519_keypair(client_ke_pubkey, client_ke_privkey);

    BIGNUM *client_ke_random_bn = BN_new();
    if (client_ke_random_bn == NULL)
    {
        LogError("[%s] Memory allocation for |client_ke_random_bn| failed",
                 current_stage);
        exit(EXIT_FAILURE);
    }

    if (!BN_rand(client_ke_random_bn,
                 CLTLS_KE_RANDOM_LENGTH * 8,
                 BN_RAND_TOP_ANY,
                 BN_RAND_BOTTOM_ANY))
    {
        LogError("[%s] BN_rand() failed: %s",
                 current_stage,
                 ERR_error_string(ERR_get_error(), NULL));
        BN_free(client_ke_random_bn);
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    if (!BN_bn2bin_padded(client_ke_random,
                          CLTLS_KE_RANDOM_LENGTH,
                          client_ke_random_bn))
    {
        LogError("[%s] BN_bn2bin_padded() failed: %s",
                 current_stage,
                 ERR_error_string(ERR_get_error(), NULL));
        BN_free(client_ke_random_bn);
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    BN_free(client_ke_random_bn);

    ByteVecResize(&send_buffer, CLTLS_COMMON_HEADER_LENGTH);

    ByteVecPushBack(&send_buffer, ctx->application_layer_protocol);
    ByteVecPushBackBlock(&send_buffer, ctx->client_identity, ENTITY_IDENTITY_LENGTH);
    ByteVecPushBack(&send_buffer, ctx->client_cipher_suite_set->size);
    foreach (set_CipherSuite, ctx->client_cipher_suite_set, cipher_suite)
    {
        ByteVecPushBack(&send_buffer, cipher_suite.ref->cipher_suite);
    }
    ByteVecPushBackBlock(&send_buffer, client_ke_pubkey, CLTLS_KE_PUBLIC_KEY_LENGTH);
    ByteVecPushBackBlock(&send_buffer, client_ke_random, CLTLS_KE_RANDOM_LENGTH);

    CLTLS_SET_COMMON_HEADER(send_buffer.data,
                            CLTLS_MSG_TYPE_CLIENT_HELLO,
                            send_buffer.size - CLTLS_COMMON_HEADER_LENGTH);

    if (!TcpSend(ctx->socket_fd,
                 send_buffer.data,
                 send_buffer.size))
    {
        LogError("[%s] Failed to send CLIENT_HELLO to server",
                 current_stage);
        CLOSE_FREE_RETURN;
    }

    return true;
}