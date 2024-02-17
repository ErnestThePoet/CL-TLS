#include "server_tcp_request_handler.h"

void *ServerTcpRequestHandler(void *arg)
{
    const TcpRequestHandlerCtx *ctx = (const TcpRequestHandlerCtx *)arg;
    const ServerArgs *server_args = (const ServerArgs *)ctx->extra;

    // [Receive] Client Hello
    uint8_t receive_common_header[CLTLS_COMMON_HEADER_LENGTH];
    if (!TcpRecv(ctx->client_socket_fd,
                 receive_common_header,
                 CLTLS_COMMON_HEADER_LENGTH))
    {
        LogError("Failed to receive common header of CLIENT_HELLO");
        CLOSE_FREE_ARG_RETURN;
    }

    if (CLTLS_MSG_TYPE(receive_common_header) != CLTLS_MSG_TYPE_CLIENT_HELLO &&
        CLTLS_MSG_TYPE(receive_common_header) != CLTLS_MSG_TYPE_ERROR_STOP_NOTIFY)
    {
        LogError("Invalid packet received, expecting CLIENT_HELLO");
        CLOSE_FREE_ARG_RETURN;
    }

    size_t receive_remaining_length = CLTLS_REMAINING_LENGTH(receive_common_header);

    uint8_t *receive_remaining = malloc(receive_remaining_length);
    if (receive_remaining == NULL)
    {
        LogError("Memory allocation for |receive_remaining| failed");
        CLOSE_FREE_ARG_RETURN;
    }

    size_t send_length = CLTLS_SERVER_HELLO_HEADER_LENGTH;
    uint8_t *send_data = malloc(send_length);
    if (send_data == NULL)
    {
        LogError("Memory allocation for |send_data| failed");
        free(receive_remaining);
        CLOSE_FREE_ARG_RETURN;
    }

    size_t traffic_capacity = INITIAL_TRAFFIC_CAPACITY;
    size_t traffic_length = 0;
    uint8_t *traffic = malloc(traffic_capacity);
    if (traffic == NULL)
    {
        LogError("Memory allocation for |traffic| failed");
        free(receive_remaining);
        free(send_data);
        CLOSE_FREE_ARG_RETURN;
    }

    if (!TcpRecv(ctx->client_socket_fd,
                 receive_remaining,
                 receive_remaining_length))
    {
        LogError("Failed to receive remaining part of CLIENT_HELLO");
        CLOSE_FREE_ARG_BUF_RETURN;
    }

    CHECK_ERROR_STOP_NOTIFY;

    APPEND_TRAFFIC(receive_common_header, CLTLS_COMMON_HEADER_LENGTH);
    APPEND_TRAFFIC(receive_remaining, receive_remaining_length);

    const uint8_t application_layer_protocol = receive_remaining[0];

    // In proxy mode, check client identity
    if (server_args->mode == SERVER_MODE_PROXY)
    {
        Id client_id;
        memcpy(client_id.id,
               receive_remaining + CLTLS_APPLICATION_LAYER_PROTOCOL_LENGTH,
               CLTLS_IDENTITY_LENGTH);
        char client_id_hex[CLTLS_IDENTITY_LENGTH * 2 + 1] = {0};
        for (int i = 0; i < CLTLS_IDENTITY_LENGTH; i++)
        {
            sprintf(client_id_hex + i * 2, "%02hhX", client_id.id[i]);
        }
        client_id_hex[CLTLS_IDENTITY_LENGTH * 2] = '\0';

        if (set_Id_find(&kServerPermittedIdSet, client_id) ==
            set_Id_end(&kServerPermittedIdSet))
        {
            LogWarn("Unauthorized client: %s, connection refused", client_id_hex);
            SEND_ERROR_STOP_NOTIFY_RETURN(CLTLS_ERROR_IDENTITY_NOT_PERMITTED);
        }
        else
        {
            LogInfo("Authorized client: %s", client_id_hex);
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
        CLOSE_FREE_ARG_BUF_RETURN;
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

    BN_free(server_ke_random_bn);

    CLTLS_SET_COMMON_HEADER(
        send_data,
        CLTLS_MSG_TYPE_SERVER_HELLO,
        (CLTLS_SERVER_HELLO_HEADER_LENGTH - CLTLS_COMMON_HEADER_LENGTH));

    uint8_t selected_cipher_suite = ChooseCipherSuite(
        receive_remaining[CLTLS_APPLICATION_LAYER_PROTOCOL_LENGTH +
                          CLTLS_IDENTITY_LENGTH],
        receive_remaining +
            CLTLS_APPLICATION_LAYER_PROTOCOL_LENGTH +
            CLTLS_IDENTITY_LENGTH +
            CLTLS_CIPHER_SUITE_COUNT_LENGTH,
        server_args->preferred_cipher_suite);
    if (selected_cipher_suite == CLTLS_CIPHER_NONE)
    {
        LogError("None of client's cipher suites is supported");
        SEND_ERROR_STOP_NOTIFY_RETURN(CLTLS_ERROR_NO_SUPPORTED_CIPHER_SUITE);
    }

    const HashScheme *hash = NULL;
    const AeadScheme *aead = NULL;
    const EVP_MD *md_hmac_hkdf = NULL;
    GetCryptoSchemes(selected_cipher_suite, &hash, &aead, &md_hmac_hkdf);

    send_data[CLTLS_COMMON_HEADER_LENGTH] = selected_cipher_suite;
    memcpy(send_data +
               CLTLS_COMMON_HEADER_LENGTH +
               CLTLS_CIPHER_SUITE_LENGTH,
           server_ke_pubkey,
           CLTLS_KE_PUBKEY_LENGTH);
    memcpy(send_data +
               CLTLS_COMMON_HEADER_LENGTH +
               CLTLS_CIPHER_SUITE_LENGTH +
               CLTLS_KE_PUBKEY_LENGTH,
           server_ke_random,
           CLTLS_KE_RANDOM_LENGTH);

    if (!TcpSend(ctx->client_socket_fd, send_data, send_length))
    {
        LogError("Failed to send SERVER_HELLO to client");
        CLOSE_FREE_ARG_BUF_RETURN;
    }

    APPEND_TRAFFIC(send_data, send_length);

    // [Server Application Keys Calc]
    uint8_t shared_secret[32] = {0};
    if (!X25519(shared_secret,
                server_ke_privkey,
                receive_remaining +
                    receive_remaining_length -
                    CLTLS_KE_RANDOM_LENGTH - CLTLS_KE_PUBKEY_LENGTH))
    {
        LogError("X25519() failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        SEND_ERROR_STOP_NOTIFY_RETURN(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    // Used as both secret and salt
    uint8_t early_secret_secret_salt[MAX_HASH_LENGTH] = {0};
    uint8_t secret_info[MAX_HASH_LENGTH + 20] = "derived";
    uint8_t derived_secret[MAX_HASH_LENGTH] = {0};

    hash->Hash("", 0, secret_info + 7);

    if (!HKDF(derived_secret, hash->hash_size,
              md_hmac_hkdf,
              early_secret_secret_salt, hash->hash_size,
              early_secret_secret_salt, hash->hash_size,
              secret_info, hash->hash_size + 7))
    {
        LogError("HKDF() for |derived_secret| failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        SEND_ERROR_STOP_NOTIFY_RETURN(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    uint8_t client_secret[MAX_HASH_LENGTH] = {0};
    uint8_t server_secret[MAX_HASH_LENGTH] = {0};

    hash->Hash(traffic, traffic_length, secret_info + 12);

    memcpy(secret_info, "c hs traffic", 12);

    if (!HKDF(client_secret, hash->hash_size,
              md_hmac_hkdf,
              shared_secret, 32, // Limited by X25519
              derived_secret, hash->hash_size,
              secret_info, hash->hash_size + 12))
    {
        LogError("HKDF() for |client_secret| failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        SEND_ERROR_STOP_NOTIFY_RETURN(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    memcpy(secret_info, "s hs traffic", 12);

    if (!HKDF(server_secret, hash->hash_size,
              md_hmac_hkdf,
              shared_secret, 32,
              derived_secret, hash->hash_size,
              secret_info, hash->hash_size + 12))
    {
        LogError("HKDF() for |server_secret| failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        SEND_ERROR_STOP_NOTIFY_RETURN(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    uint8_t client_handshake_key[MAX_ENC_KEY_LENGTH] = {0};
    uint8_t server_handshake_key[MAX_ENC_KEY_LENGTH] = {0};
    uint8_t client_handshake_npub_iv[MAX_NPUB_IV_LENGTH] = {0};
    uint8_t server_handshake_npub_iv[MAX_NPUB_IV_LENGTH] = {0};

    if (!HKDF_expand(client_handshake_key, aead->key_size,
                     md_hmac_hkdf,
                     client_secret, hash->hash_size,
                     "key", 3))
    {
        LogError("HKDF_expand() for |client_handshake_key| failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        SEND_ERROR_STOP_NOTIFY_RETURN(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    if (!HKDF_expand(server_handshake_key, aead->key_size,
                     md_hmac_hkdf,
                     server_secret, hash->hash_size,
                     "key", 3))
    {
        LogError("HKDF_expand() for |client_handshake_key| failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        SEND_ERROR_STOP_NOTIFY_RETURN(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    if (!HKDF_expand(client_handshake_npub_iv, aead->npub_iv_size,
                     md_hmac_hkdf,
                     client_secret, hash->hash_size,
                     "iv", 2))
    {
        LogError("HKDF_expand() for |client_handshake_npub_iv| failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        SEND_ERROR_STOP_NOTIFY_RETURN(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    if (!HKDF_expand(server_handshake_npub_iv, aead->npub_iv_size,
                     md_hmac_hkdf,
                     server_secret, hash->hash_size,
                     "iv", 2))
    {
        LogError("HKDF_expand() for |server_handshake_npub_iv| failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        SEND_ERROR_STOP_NOTIFY_RETURN(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    

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