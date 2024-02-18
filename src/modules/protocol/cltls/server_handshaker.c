#include "server_handshaker.h"

static bool CheckApplicationLayerProtocol(const ServerMode server_mode,
                                          const uint8_t application_layer_protocol)
{
    switch (server_mode)
    {
    case SERVER_MODE_PROXY:
        return application_layer_protocol == CLTLS_PROTOCOL_KGC ||
               application_layer_protocol == CLTLS_PROTOCOL_MQTT;
    case SERVER_MODE_KGC:
        return application_layer_protocol == CLTLS_PROTOCOL_KGC ||
               application_layer_protocol == CLTLS_PROTOCOL_KGC_REGISTER_REQUEST;
    default:
        return false;
    }
}

static uint8_t ChooseCipherSuite(set_CipherSuite *server_cipher_suite_set,
                                 const uint8_t client_cipher_suite_count,
                                 const uint8_t *client_cipher_suites,
                                 const uint8_t preferred_cipher_suite)
{
    bool client_supports_preferred_cipher_suite = false;
    for (int i = 0; i < client_cipher_suite_count; i++)
    {
        if (client_cipher_suites[i] == preferred_cipher_suite)
        {
            client_supports_preferred_cipher_suite = true;
            break;
        }
    }

    if (client_supports_preferred_cipher_suite &&
        set_CipherSuite_find(
            server_cipher_suite_set,
            (CipherSuite){.cipher_suite = preferred_cipher_suite}) !=
            set_CipherSuite_end(server_cipher_suite_set))
    {
        return preferred_cipher_suite;
    }

    // Return first cipher suite that both parties support
    for (int i = 0; i < client_cipher_suite_count; i++)
    {
        if (set_CipherSuite_find(
                server_cipher_suite_set,
                (CipherSuite){.cipher_suite = client_cipher_suites[i]}) !=
            set_CipherSuite_end(server_cipher_suite_set))
        {
            return client_cipher_suites[i];
        }
    }

    return CLTLS_CIPHER_NONE;
}

bool ServerHandshake(const ServerHandshakeCtx *ctx,
                     HandshakeResult *handshake_result_ret)
{
    ByteVec receive_buffer;
    ByteVec send_buffer;
    ByteVec traffic_buffer;

    ByteVecInitWithCapacity(&receive_buffer, INITIAL_SOCKET_BUFFER_CAPACITY);
    ByteVecInitWithCapacity(&send_buffer, INITIAL_SOCKET_BUFFER_CAPACITY);
    ByteVecInitWithCapacity(&traffic_buffer, INITIAL_TRAFFIC_BUFFER_CAPACITY);

    // [Receive] Client Hello
    ByteVecResize(&receive_buffer, CLTLS_COMMON_HEADER_LENGTH);

    if (!TcpRecv(ctx->client_socket_fd,
                 receive_buffer.data,
                 CLTLS_COMMON_HEADER_LENGTH))
    {
        LogError("Failed to receive common header of CLIENT_HELLO");
        CLOSE_FREE_RETURN;
    }

    if (CLTLS_MSG_TYPE(receive_buffer.data) != CLTLS_MSG_TYPE_CLIENT_HELLO &&
        CLTLS_MSG_TYPE(receive_buffer.data) != CLTLS_MSG_TYPE_ERROR_STOP_NOTIFY)
    {
        LogError("Invalid packet received, expecting CLIENT_HELLO");
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_UNEXPECTED_MSG_TYPE);
    }

    size_t receive_remaining_length = CLTLS_REMAINING_LENGTH(receive_buffer.data);

    ByteVecResizeBy(&receive_buffer, receive_remaining_length);

    if (!TcpRecv(ctx->client_socket_fd,
                 CLTLS_REMAINING_HEADER(receive_buffer.data),
                 receive_remaining_length))
    {
        LogError("Failed to receive remaining part of CLIENT_HELLO");
        CLOSE_FREE_RETURN;
    }

    CHECK_ERROR_STOP_NOTIFY;

    ByteVecPushBackBlockFromByteVec(&traffic_buffer, &receive_buffer);

    const uint8_t application_layer_protocol =
        CLTLS_REMAINING_HEADER(receive_buffer.data)[0];

    if (!CheckApplicationLayerProtocol(ctx->mode, application_layer_protocol))
    {
        LogError("Invalid application layer protocol 0x%02hhX",
                 application_layer_protocol);
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INVALID_APPLICATION_LAYER_PROTOCOL);
    }

    // In proxy mode, check KGC/client identity
    if (ctx->mode == SERVER_MODE_PROXY)
    {
        Id client_id;
        memcpy(client_id.id,
               CLTLS_REMAINING_HEADER(receive_buffer.data) +
                   CLTLS_APPLICATION_LAYER_PROTOCOL_LENGTH,
               ENTITY_IDENTITY_LENGTH);

        char client_id_hex[ENTITY_IDENTITY_HEX_STR_LENGTH] = {0};
        IdentityBin2Hex(client_id.id, client_id_hex);

        if (application_layer_protocol == CLTLS_PROTOCOL_KGC)
        {
            if (memcmp(kKgcIdentity,
                       client_id.id,
                       ENTITY_IDENTITY_LENGTH))
            {
                LogWarn("CLTLS_PROTOCOL_KGC message sender is not KGC (identity: %s), connection refused", client_id_hex);
                SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_IDENTITY_NOT_PERMITTED);
            }
        }
        else
        {
            if (set_Id_find(ctx->server_permitted_id_set, client_id) ==
                set_Id_end(ctx->server_permitted_id_set))
            {
                LogWarn("Unauthorized client: %s, connection refused", client_id_hex);
                SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_IDENTITY_NOT_PERMITTED);
            }
            else
            {
                LogInfo("Authorized client: %s", client_id_hex);
            }
        }
    }

    // [Send] Server Hello
    uint8_t server_ke_pubkey[CLTLS_KE_PUBLIC_KEY_LENGTH] = {0};
    uint8_t server_ke_privkey[CLTLS_KE_PRIVATE_KEY_LENGTH] = {0};
    uint8_t server_ke_random[CLTLS_KE_RANDOM_LENGTH] = {0};
    X25519_keypair(server_ke_pubkey, server_ke_privkey);

    BIGNUM *server_ke_random_bn = BN_new();
    if (server_ke_random_bn == NULL)
    {
        LogError("Memory allocation for |server_ke_random_bn| failed");
        exit(EXIT_FAILURE);
    }

    if (!BN_rand(server_ke_random_bn,
                 CLTLS_KE_RANDOM_LENGTH * 8,
                 BN_RAND_TOP_ANY,
                 BN_RAND_BOTTOM_ANY))
    {
        LogError("BN_rand() failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        BN_free(server_ke_random_bn);
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    if (!BN_bn2bin_padded(server_ke_random,
                          CLTLS_KE_RANDOM_LENGTH,
                          server_ke_random_bn))
    {
        LogError("BN_bn2bin_padded() failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        BN_free(server_ke_random_bn);
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    BN_free(server_ke_random_bn);

    ByteVecResize(&send_buffer, CLTLS_COMMON_HEADER_LENGTH);

    CLTLS_SET_COMMON_HEADER(
        send_buffer.data,
        CLTLS_MSG_TYPE_SERVER_HELLO,
        (CLTLS_SERVER_HELLO_HEADER_LENGTH - CLTLS_COMMON_HEADER_LENGTH));

    uint8_t selected_cipher_suite = ChooseCipherSuite(
        ctx->server_cipher_suite_set,
        CLTLS_REMAINING_HEADER(receive_buffer.data)
            [CLTLS_APPLICATION_LAYER_PROTOCOL_LENGTH +
             ENTITY_IDENTITY_LENGTH],
        CLTLS_REMAINING_HEADER(receive_buffer.data) +
            CLTLS_APPLICATION_LAYER_PROTOCOL_LENGTH +
            ENTITY_IDENTITY_LENGTH +
            CLTLS_CIPHER_SUITE_COUNT_LENGTH,
        ctx->preferred_cipher_suite);
    if (selected_cipher_suite == CLTLS_CIPHER_NONE)
    {
        LogError("None of client's cipher suites is supported");
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_NO_SUPPORTED_CIPHER_SUITE);
    }

    const HashScheme *hash = NULL;
    const AeadScheme *aead = NULL;
    const EVP_MD *md_hmac_hkdf = NULL;
    GetCryptoSchemes(selected_cipher_suite, &hash, &aead, &md_hmac_hkdf);

    ByteVecPushBack(&send_buffer, selected_cipher_suite);
    ByteVecPushBackBlock(&send_buffer, server_ke_pubkey, CLTLS_KE_PUBLIC_KEY_LENGTH);
    ByteVecPushBackBlock(&send_buffer, server_ke_random, CLTLS_KE_RANDOM_LENGTH);

    if (!TcpSend(ctx->client_socket_fd,
                 send_buffer.data,
                 CLTLS_SERVER_HELLO_HEADER_LENGTH))
    {
        LogError("Failed to send SERVER_HELLO to client");
        CLOSE_FREE_RETURN;
    }

    ByteVecPushBackBlockFromByteVec(&traffic_buffer, &send_buffer);

    // [Server Application Keys Calc]
    uint8_t shared_secret[32] = {0};
    if (!X25519(shared_secret,
                server_ke_privkey,
                receive_buffer.data +
                    receive_buffer.size -
                    CLTLS_KE_RANDOM_LENGTH - CLTLS_KE_PUBLIC_KEY_LENGTH))
    {
        LogError("X25519() failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    // Used as both secret and salt
    // Reused later as:
    // traffic_hash
    uint8_t early_secret_secret_salt[MAX_HASH_LENGTH] = {0};
    // Reused later as:
    // HKDF-Expand secret_info in Server Handshake Finished
    uint8_t secret_info[MAX_HASH_LENGTH + 20] = "derived";
    // Reused later as:
    // finished_key in Server Handshake Finished
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
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    uint8_t client_secret[MAX_HASH_LENGTH] = {0};
    uint8_t server_secret[MAX_HASH_LENGTH] = {0};

    hash->Hash(traffic_buffer.data, traffic_buffer.size, secret_info + 12);

    memcpy(secret_info, "c hs traffic", 12);

    if (!HKDF(client_secret, hash->hash_size,
              md_hmac_hkdf,
              shared_secret, 32, // Limited by X25519
              derived_secret, hash->hash_size,
              secret_info, hash->hash_size + 12))
    {
        LogError("HKDF() for |client_secret| failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
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
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
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
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    if (!HKDF_expand(server_handshake_key, aead->key_size,
                     md_hmac_hkdf,
                     server_secret, hash->hash_size,
                     "key", 3))
    {
        LogError("HKDF_expand() for |client_handshake_key| failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    if (!HKDF_expand(client_handshake_npub_iv, aead->npub_iv_size,
                     md_hmac_hkdf,
                     client_secret, hash->hash_size,
                     "iv", 2))
    {
        LogError("HKDF_expand() for |client_handshake_npub_iv| failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    if (!HKDF_expand(server_handshake_npub_iv, aead->npub_iv_size,
                     md_hmac_hkdf,
                     server_secret, hash->hash_size,
                     "iv", 2))
    {
        LogError("HKDF_expand() for |server_handshake_npub_iv| failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    // [Send] Server Public Key

    // Max encrypted size is plain text size + max enc block size
    ByteVecResize(&send_buffer,
                  CLTLS_COMMON_HEADER_LENGTH +
                      CLTLS_ENTITY_PUBLIC_KEY_LENGTH +
                      MAX_ENC_BLOCK_SIZE);

    size_t encrypted_length = 0;
    // Used for AES only
    size_t iv_length = aead->npub_iv_size;

    if (!aead->Encrypt(ctx->server_public_key, CLTLS_ENTITY_PUBLIC_KEY_LENGTH,
                       CLTLS_REMAINING_HEADER(send_buffer.data), &encrypted_length,
                       NULL, 0,
                       server_handshake_key,
                       server_handshake_npub_iv,
                       &iv_length))
    {
        LogError("Encryption of |kServerPublicKey| failed");
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    ByteVecResize(&send_buffer, CLTLS_COMMON_HEADER_LENGTH + encrypted_length);

    CLTLS_SET_COMMON_HEADER(send_buffer.data,
                            CLTLS_MSG_TYPE_SERVER_PUBKEY,
                            encrypted_length);

    if (!TcpSend(ctx->client_socket_fd,
                 send_buffer.data,
                 send_buffer.size))
    {
        LogError("Failed to send SERVER_PUBKEY to client");
        CLOSE_FREE_RETURN;
    }

    ByteVecPushBackBlockFromByteVec(&traffic_buffer, &send_buffer);

    // [Send] Server Public Key Verify

    // Reuse stack space
    uint8_t *traffic_hash = early_secret_secret_salt;
    uint8_t traffic_signature[CLTLS_TRAFFIC_SIGNATURE_LENGTH] = {0};

    hash->Hash(traffic_buffer.data, traffic_buffer.size, traffic_hash);

    if (!ED25519_sign(traffic_signature,
                      traffic_hash,
                      hash->hash_size,
                      ctx->server_private_key))
    {
        LogError("ED25519_sign() for |traffic_hash| failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    ByteVecResize(&send_buffer,
                  CLTLS_COMMON_HEADER_LENGTH +
                      CLTLS_TRAFFIC_SIGNATURE_LENGTH +
                      MAX_ENC_BLOCK_SIZE);

    if (!aead->Encrypt(traffic_signature, CLTLS_TRAFFIC_SIGNATURE_LENGTH,
                       CLTLS_REMAINING_HEADER(send_buffer.data), &encrypted_length,
                       NULL, 0,
                       server_handshake_key,
                       server_handshake_npub_iv,
                       &iv_length))
    {
        LogError("Encryption of |traffic_signature| failed");
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    ByteVecResize(&send_buffer, CLTLS_COMMON_HEADER_LENGTH + encrypted_length);

    CLTLS_SET_COMMON_HEADER(send_buffer.data,
                            CLTLS_MSG_TYPE_SERVER_PUBKEY_VERIFY,
                            encrypted_length);

    if (!TcpSend(ctx->client_socket_fd,
                 send_buffer.data,
                 send_buffer.size))
    {
        LogError("Failed to send SERVER_PUBKEY_VERIFY to client");
        CLOSE_FREE_RETURN;
    }

    ByteVecPushBackBlockFromByteVec(&traffic_buffer, &send_buffer);

    // Only when application layer protocol is CLTLS_PROTOCOL_KGC_REGISTER_REQUEST
    // will we omit Server Public Key Request
    if (application_layer_protocol != CLTLS_PROTOCOL_KGC_REGISTER_REQUEST)
    {
        // [Send] Server Public Key Request
        ByteVecResize(&send_buffer, CLTLS_SERVER_PUBKEY_REQUEST_HEADER_LENGTH);
        CLTLS_SET_COMMON_HEADER(send_buffer.data,
                                CLTLS_MSG_TYPE_SERVER_PUBKEY_REQUEST,
                                0);

        if (!TcpSend(ctx->client_socket_fd,
                     send_buffer.data,
                     CLTLS_SERVER_PUBKEY_REQUEST_HEADER_LENGTH))
        {
            LogError("Failed to send SERVER_PUBKEY_REQUEST to client");
            CLOSE_FREE_RETURN;
        }

        ByteVecPushBackBlockFromByteVec(&traffic_buffer, &send_buffer);
    }

    // [Send] Server Handshake Finished
    memcpy(secret_info, "finished", 8);
    uint8_t *finished_key = derived_secret;

    if (!HKDF_expand(finished_key, hash->hash_size,
                     md_hmac_hkdf,
                     server_secret, hash->hash_size,
                     secret_info, 8))
    {
        LogError("HKDF_expand() for |finished_key| failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    hash->Hash(traffic_buffer.data, traffic_buffer.size, traffic_hash);

    uint8_t verify_data[MAX_HASH_LENGTH] = {0};
    unsigned int verify_data_length = 0;

    if (HMAC(md_hmac_hkdf,
             finished_key, hash->hash_size,
             traffic_hash, hash->hash_size,
             verify_data, &verify_data_length) == NULL)
    {
        LogError("HMAC() for |verify_data| failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    ByteVecResize(&send_buffer,
                  CLTLS_COMMON_HEADER_LENGTH +
                      verify_data_length +
                      MAX_ENC_BLOCK_SIZE);

    if (!aead->Encrypt(verify_data, verify_data_length,
                       CLTLS_REMAINING_HEADER(send_buffer.data), &encrypted_length,
                       NULL, 0,
                       server_handshake_key,
                       server_handshake_npub_iv,
                       &iv_length))
    {
        LogError("Encryption of |verify_data| failed");
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    ByteVecResize(&send_buffer, CLTLS_COMMON_HEADER_LENGTH + encrypted_length);

    CLTLS_SET_COMMON_HEADER(send_buffer.data,
                            CLTLS_MSG_TYPE_SERVER_HANDSHAKE_FINISHED,
                            encrypted_length);

    if (!TcpSend(ctx->client_socket_fd,
                 send_buffer.data,
                 send_buffer.size))
    {
        LogError("Failed to send SERVER_HANDSHAKE_FINISHED to client");
        CLOSE_FREE_RETURN;
    }

    ByteVecPushBackBlockFromByteVec(&traffic_buffer, &send_buffer);

    return true;
}
