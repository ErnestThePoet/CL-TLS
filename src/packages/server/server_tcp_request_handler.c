#include "server_tcp_request_handler.h"

void *ServerTcpRequestHandler(void *arg)
{
    const TcpRequestHandlerCtx *ctx = (const TcpRequestHandlerCtx *)arg;
    const ServerArgs *server_args = (const ServerArgs *)ctx->extra;

    // [Receive] Client Hello
    uint8_t common_header[CLTLS_COMMON_HEADER_LENGTH];
    if (!TcpRecv(ctx->client_socket_fd,
                 common_header,
                 CLTLS_COMMON_HEADER_LENGTH))
    {
        CLOSE_FREE_RETURN;
    }

    if (CLTLS_MSG_TYPE(common_header) != CLTLS_MSG_TYPE_CLIENT_HELLO &&
        CLTLS_MSG_TYPE(common_header) != CLTLS_MSG_TYPE_ERROR_STOP_NOTIFY)
    {
        LogError("Invalid packet received, expecting CLIENT_HELLO");
        CLOSE_FREE_RETURN;
    }

    size_t remaining_length = REMAINING_LENGTH(common_header);

    uint8_t *receive_remaining = malloc(remaining_length);
    if (receive_remaining == NULL)
    {
        LogError("Memory allocation for |receive_remaining| failed");
        CLOSE_FREE_RETURN;
    }

    uint8_t *send_data = malloc(CLTLS_SERVER_HELLO_HEADER_LENGTH);
    if (send_data == NULL)
    {
        LogError("Memory allocation for |send_data| failed");
        free(receive_remaining);
        CLOSE_FREE_RETURN;
    }

    if (!TcpRecv(ctx->client_socket_fd,
                 receive_remaining,
                 remaining_length))
    {
        CLOSE_FREE2_RETURN;
    }

    CHECK_ERROR_STOP_NOTIFY;

    const uint8_t application_layer_protocol = receive_remaining[0];

    // In proxy mode, check client identity
    if (server_args->mode == SERVER_MODE_PROXY)
    {
        Id client_id;
        memcpy(client_id.id, receive_remaining + 1, CLTLS_IDENTITY_LENGTH);
        if (set_Id_find(&kServerPermittedIdSet, client_id) ==
            set_Id_end(&kServerPermittedIdSet))
        {
            SEND_ERROR_STOP_NOTIFY_RETURN(CLTLS_ERROR_IDENTITY_NOT_PERMITTED);
        }
    }

    // [Send] Server Hello
    uint8_t server_ke_pubkey[CLTLS_KE_PUBKEY_LENGTH] = {0};
    uint8_t server_ke_privkey[CLTLS_KE_PRIVKEY_LENGTH] = {0};
    uint8_t server_ke_random[CLTLS_KE_RANDOM_LENGTH] = {0};
    X25519_keypair(server_ke_pubkey, server_ke_privkey);

    BIGNUM *server_ke_random_bn = BN_new();
    if (server_ke_random_bn == NULL)
    {
        LogError("Memory allocation for |server_ke_random_bn| failed");
        CLOSE_FREE2_RETURN;
    }

    if (!BN_rand(server_ke_random_bn,
                 CLTLS_KE_RANDOM_LENGTH * 8,
                 BN_RAND_TOP_ANY,
                 BN_RAND_BOTTOM_ANY))
    {
        LogError("BN_rand() failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        BN_free(server_ke_random_bn);
        SEND_ERROR_STOP_NOTIFY_RETURN(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    if (!BN_bn2bin_padded(server_ke_random,
                          CLTLS_KE_RANDOM_LENGTH,
                          server_ke_random_bn))
    {
        LogError("BN_bn2bin_padded() failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        BN_free(server_ke_random_bn);
        SEND_ERROR_STOP_NOTIFY_RETURN(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    CLTLS_SET_COMMON_HEADER(
        send_data,
        CLTLS_MSG_TYPE_SERVER_HELLO,
        (CLTLS_SERVER_HELLO_HEADER_LENGTH - CLTLS_COMMON_HEADER_LENGTH));
    
    

    return NULL;
}

uint8_t ChooseCipherSuite(const uint8_t cipher_suite_count,
                          const uint8_t *cipher_suites,
                          const uint8_t preferred_cipher_suite)
{
    bool client_supports_preferred_cipher_suite = false;
    for (int i = 0; i < cipher_suite_count; i++)
    {
        if (cipher_suites[i] == preferred_cipher_suite)
        {
            client_supports_preferred_cipher_suite = true;
            break;
        }
    }

    if (client_supports_preferred_cipher_suite &&
        set_CipherSuite_find(
            &kServerCipherSuiteSet,
            (CipherSuite){.cipher_suite = preferred_cipher_suite}) !=
            set_CipherSuite_end(&kServerCipherSuiteSet))
    {
        return preferred_cipher_suite;
    }

    // Return first cipher suite that both parties support
    for (int i = 0; i < cipher_suite_count; i++)
    {
        if (set_CipherSuite_find(
                &kServerCipherSuiteSet,
                (CipherSuite){.cipher_suite = cipher_suites[i]}) !=
            set_CipherSuite_end(&kServerCipherSuiteSet))
        {
            return cipher_suites[i];
        }
    }

    return CLTLS_CIPHER_NONE;
}