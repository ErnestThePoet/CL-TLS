#include "server_handshake.h"

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
                     HandshakeResult *handshake_result_ret,
                     uint8_t *application_layer_protocol_ret)
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

    // [Receive] Client Hello
    const char *current_stage = "RECEIVE Client Hello";

    HANDSHAKE_RECEIVE(CLIENT_HELLO, true);

    const uint8_t application_layer_protocol =
        CLTLS_REMAINING_HEADER(receive_buffer.data)[0];

    if (!CheckApplicationLayerProtocol(ctx->mode, application_layer_protocol))
    {
        LogError("[%s] Invalid application layer protocol 0x%02hhX",
                 current_stage,
                 current_stage,
                 application_layer_protocol);
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INVALID_APPLICATION_LAYER_PROTOCOL);
    }

    *application_layer_protocol_ret = application_layer_protocol;

    uint8_t client_identity[ENTITY_IDENTITY_LENGTH] = {0};
    memcpy(client_identity,
           CLTLS_REMAINING_HEADER(receive_buffer.data) +
               CLTLS_APPLICATION_LAYER_PROTOCOL_LENGTH,
           ENTITY_IDENTITY_LENGTH);

    // In proxy mode, check KGC/client identity
    if (ctx->mode == SERVER_MODE_PROXY)
    {
        Id client_id;
        memcpy(client_id.id,
               CLTLS_REMAINING_HEADER(receive_buffer.data) +
                   CLTLS_APPLICATION_LAYER_PROTOCOL_LENGTH,
               ENTITY_IDENTITY_LENGTH);

        char client_id_hex[ENTITY_IDENTITY_HEX_STR_LENGTH] = {0};
        Bin2Hex(client_id.id, client_id_hex, ENTITY_IDENTITY_LENGTH);

        if (application_layer_protocol == CLTLS_PROTOCOL_KGC)
        {
            if (memcmp(kKgcIdentity,
                       client_id.id,
                       ENTITY_IDENTITY_LENGTH))
            {
                LogWarn("CLTLS_PROTOCOL_KGC message sender "
                        "is not KGC (identity: %s), connection refused",
                        client_id_hex);
                HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
                    CLTLS_ERROR_IDENTITY_NOT_PERMITTED);
            }
        }
        else
        {
            if (set_Id_find(ctx->server_permitted_id_set, client_id) ==
                set_Id_end(ctx->server_permitted_id_set))
            {
                LogWarn("Unauthorized client: %s, connection refused", client_id_hex);
                HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
                    CLTLS_ERROR_IDENTITY_NOT_PERMITTED);
            }
            else
            {
                LogInfo("Authorized client: %s", client_id_hex);
            }
        }
    }

    // [Send] Server Hello
    current_stage = "SEND Server Hello";

    uint8_t self_ke_public_key[CLTLS_KE_PUBLIC_KEY_LENGTH] = {0};
    uint8_t self_ke_private_key[CLTLS_KE_PRIVATE_KEY_LENGTH] = {0};
    uint8_t self_ke_random[CLTLS_KE_RANDOM_LENGTH] = {0};

    GENERATE_KE_KEY_RANDOM;

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
        LogError("[%s] None of client's cipher suites is supported",
                 current_stage);
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_NO_SUPPORTED_CIPHER_SUITE);
    }

    const HashScheme *hash = NULL;
    const AeadScheme *aead = NULL;
    const EVP_MD *md_hmac_hkdf = NULL;
    GetCryptoSchemes(selected_cipher_suite, &hash, &aead, &md_hmac_hkdf);

    ByteVecResize(&send_buffer, CLTLS_COMMON_HEADER_LENGTH);

    CLTLS_SET_COMMON_HEADER(
        send_buffer.data,
        CLTLS_MSG_TYPE_SERVER_HELLO,
        (CLTLS_SERVER_HELLO_HEADER_LENGTH - CLTLS_COMMON_HEADER_LENGTH));

    ByteVecPushBack(&send_buffer, selected_cipher_suite);
    ByteVecPushBackBlock(&send_buffer, self_ke_public_key, CLTLS_KE_PUBLIC_KEY_LENGTH);
    ByteVecPushBackBlock(&send_buffer, self_ke_random, CLTLS_KE_RANDOM_LENGTH);

    // send_size convention:
    // For fixed length header, use macro;
    // Otherwise, use send_buffer.size
    if (!TcpSend(ctx->socket_fd,
                 send_buffer.data,
                 CLTLS_SERVER_HELLO_HEADER_LENGTH))
    {
        LogError("[%s] Failed to send SERVER_HELLO",
                 current_stage);
        HANDSHAKE_FREE_RETURN_FALSE;
    }

    ByteVecPushBackBlockFromByteVec(&traffic_buffer, &send_buffer);

    // [Server Handshake Keys Calc]
    current_stage = "Server Handshake Keys Calc";

    uint8_t shared_secret[X25519_SHARED_KEY_LEN] = {0};
    if (!X25519(shared_secret,
                self_ke_private_key,
                receive_buffer.data +
                    receive_buffer.size -
                    CLTLS_KE_RANDOM_LENGTH - CLTLS_KE_PUBLIC_KEY_LENGTH))
    {
        LogError("[%s] X25519() failed: %s",
                 current_stage,
                 ERR_error_string(ERR_get_error(), NULL));
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    // Used as both secret and salt
    // Reused later as:
    // all-zero secret in HKDF-Extract in Server Application Keys Calc
    uint8_t early_secret_secret_salt[MAX_HASH_LENGTH] = {0};
    // Reused later as:
    // HKDF-Expand secret_info in Server Handshake Finished
    // HKDF-Expand secret_info in Server Application Keys Calc
    uint8_t secret_info[MAX_HASH_LENGTH + 20] = {0};
    // Reused later as:
    // finished_key in Server Handshake Finished
    // derived_secret in Server Application Keys Calc
    uint8_t derived_secret[MAX_HASH_LENGTH] = {0};

    // Do not reuse
    uint8_t handshake_secret[MAX_HASH_LENGTH] = {0};

    size_t hkdf_extract_out_length = 0; // No need to check

    // Do not reuse before Server Application Keys Calc
    // Reused later as:
    // client_secret in Server Application Keys Calc
    uint8_t client_secret[MAX_HASH_LENGTH] = {0};

    // Do not reuse before Server Application Keys Calc
    // Reused later as:
    // server_secret in Server Application Keys Calc
    uint8_t server_secret[MAX_HASH_LENGTH] = {0};

    uint8_t client_handshake_key[MAX_ENC_KEY_LENGTH] = {0};
    uint8_t server_handshake_key[MAX_ENC_KEY_LENGTH] = {0};
    uint8_t client_handshake_npub_iv[MAX_NPUB_IV_LENGTH] = {0};
    uint8_t server_handshake_npub_iv[MAX_NPUB_IV_LENGTH] = {0};

    CALCULATE_HANDSHAKE_KEY;

    // [Send] Server Public Key
    current_stage = "SEND Server Public Key";

    size_t encrypted_length = 0;
    size_t decrypted_length = 0;
    // Used for AES only
    size_t iv_length = aead->npub_iv_size;

    // Max encrypted size is plain text size + max enc block size
    ByteVecResize(&send_buffer,
                  CLTLS_COMMON_HEADER_LENGTH +
                      CLTLS_ENTITY_PUBLIC_KEY_LENGTH +
                      MAX_ENC_EXTRA_SIZE);

    if (!aead->Encrypt(ctx->server_public_key, CLTLS_ENTITY_PUBLIC_KEY_LENGTH,
                       CLTLS_REMAINING_HEADER(send_buffer.data), &encrypted_length,
                       NULL, 0,
                       server_handshake_key,
                       server_handshake_npub_iv,
                       &iv_length))
    {
        LogError("[%s] Encryption of |server_public_key| failed",
                 current_stage);
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    ByteVecResize(&send_buffer, CLTLS_COMMON_HEADER_LENGTH + encrypted_length);

    CLTLS_SET_COMMON_HEADER(send_buffer.data,
                            CLTLS_MSG_TYPE_SERVER_PUBKEY,
                            encrypted_length);

    if (!TcpSend(ctx->socket_fd,
                 send_buffer.data,
                 send_buffer.size))
    {
        LogError("[%s] Failed to send SERVER_PUBKEY",
                 current_stage);
        HANDSHAKE_FREE_RETURN_FALSE;
    }

    ByteVecPushBackBlockFromByteVec(&traffic_buffer, &send_buffer);

    // [Send] Server Public Key Verify
    current_stage = "SEND Server Public Key Verify";

    uint8_t traffic_hash[MAX_HASH_LENGTH] = {0};
    uint8_t traffic_signature[CLTLS_TRAFFIC_SIGNATURE_LENGTH] = {0};

    hash->Hash(traffic_buffer.data, traffic_buffer.size, traffic_hash);

    if (!ED25519_sign(traffic_signature,
                      traffic_hash,
                      hash->hash_size,
                      ctx->server_private_key))
    {
        LogError("[%s] ED25519_sign() for |traffic_hash| failed: %s",
                 current_stage,
                 ERR_error_string(ERR_get_error(), NULL));
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    ByteVecResize(&send_buffer,
                  CLTLS_COMMON_HEADER_LENGTH +
                      CLTLS_TRAFFIC_SIGNATURE_LENGTH +
                      MAX_ENC_EXTRA_SIZE);

    if (!aead->Encrypt(traffic_signature, CLTLS_TRAFFIC_SIGNATURE_LENGTH,
                       CLTLS_REMAINING_HEADER(send_buffer.data), &encrypted_length,
                       NULL, 0,
                       server_handshake_key,
                       server_handshake_npub_iv,
                       &iv_length))
    {
        LogError("[%s] Encryption of |traffic_signature| failed",
                 current_stage);
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    ByteVecResize(&send_buffer, CLTLS_COMMON_HEADER_LENGTH + encrypted_length);

    CLTLS_SET_COMMON_HEADER(send_buffer.data,
                            CLTLS_MSG_TYPE_SERVER_PUBKEY_VERIFY,
                            encrypted_length);

    if (!TcpSend(ctx->socket_fd,
                 send_buffer.data,
                 send_buffer.size))
    {
        LogError("[%s] Failed to send SERVER_PUBKEY_VERIFY",
                 current_stage);
        HANDSHAKE_FREE_RETURN_FALSE;
    }

    ByteVecPushBackBlockFromByteVec(&traffic_buffer, &send_buffer);

    const bool should_request_public_key =
        ShouldRequestClientPublicKey(application_layer_protocol);
    if (should_request_public_key)
    {
        // [Send] Server Public Key Request
        current_stage = "SEND Server Public Key Request";

        ByteVecResize(&send_buffer, CLTLS_SERVER_PUBKEY_REQUEST_HEADER_LENGTH);
        CLTLS_SET_COMMON_HEADER(send_buffer.data,
                                CLTLS_MSG_TYPE_SERVER_PUBKEY_REQUEST,
                                0);

        if (!TcpSend(ctx->socket_fd,
                     send_buffer.data,
                     CLTLS_SERVER_PUBKEY_REQUEST_HEADER_LENGTH))
        {
            LogError("[%s] Failed to send SERVER_PUBKEY_REQUEST",
                     current_stage);
            HANDSHAKE_FREE_RETURN_FALSE;
        }

        ByteVecPushBackBlockFromByteVec(&traffic_buffer, &send_buffer);
    }

    // [Send] Server Handshake Finished
    current_stage = "SEND Server Handshake Finished";

    memcpy(secret_info, "finished", 8);
    uint8_t *finished_key = derived_secret;

    if (!HKDF_expand(finished_key, hash->hash_size,
                     md_hmac_hkdf,
                     server_secret, hash->hash_size,
                     secret_info, 8))
    {
        LogError("[%s] HKDF_expand() for |server_finished_key| failed: %s",
                 current_stage,
                 ERR_error_string(ERR_get_error(), NULL));
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    hash->Hash(traffic_buffer.data, traffic_buffer.size, traffic_hash);

    uint8_t verify_data[MAX_HASH_LENGTH] = {0};
    unsigned int verify_data_length = 0;

    if (HMAC(md_hmac_hkdf,
             finished_key, hash->hash_size,
             traffic_hash, hash->hash_size,
             verify_data, &verify_data_length) == NULL)
    {
        LogError("[%s] HMAC() for |server_verify_data| failed: %s",
                 current_stage,
                 ERR_error_string(ERR_get_error(), NULL));
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    ByteVecResize(&send_buffer,
                  CLTLS_COMMON_HEADER_LENGTH +
                      verify_data_length +
                      MAX_ENC_EXTRA_SIZE);

    if (!aead->Encrypt(verify_data, verify_data_length,
                       CLTLS_REMAINING_HEADER(send_buffer.data), &encrypted_length,
                       NULL, 0,
                       server_handshake_key,
                       server_handshake_npub_iv,
                       &iv_length))
    {
        LogError("[%s] Encryption of |server_verify_data| failed",
                 current_stage);
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    ByteVecResize(&send_buffer, CLTLS_COMMON_HEADER_LENGTH + encrypted_length);

    CLTLS_SET_COMMON_HEADER(send_buffer.data,
                            CLTLS_MSG_TYPE_SERVER_HANDSHAKE_FINISHED,
                            encrypted_length);

    if (!TcpSend(ctx->socket_fd,
                 send_buffer.data,
                 send_buffer.size))
    {
        LogError("[%s] Failed to send SERVER_HANDSHAKE_FINISHED",
                 current_stage);
        HANDSHAKE_FREE_RETURN_FALSE;
    }

    ByteVecPushBackBlockFromByteVec(&traffic_buffer, &send_buffer);

    if (should_request_public_key)
    {
        // [Receive] Client Public Key
        current_stage = "RECEIVE Client Public Key";

        HANDSHAKE_RECEIVE(CLIENT_PUBKEY, true);

        // No need to precisely control the size of decryption_buffer
        // Ciphertext length always >= plaintext length
        ByteVecResize(&decryption_buffer, receive_remaining_length);

        if (!aead->Decrypt(CLTLS_REMAINING_HEADER(receive_buffer.data),
                           receive_remaining_length,
                           decryption_buffer.data, &decrypted_length,
                           NULL, 0,
                           client_handshake_key,
                           client_handshake_npub_iv,
                           &iv_length))
        {
            LogError("[%s] Decryption of |client_public_key| failed",
                     current_stage);
            HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
                CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
        }

        if (decrypted_length != CLTLS_ENTITY_PUBLIC_KEY_LENGTH)
        {
            LogError("[%s] Client public key length is %zu, expected %zu",
                     current_stage,
                     decrypted_length,
                     CLTLS_ENTITY_PUBLIC_KEY_LENGTH);
            HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
                CLTLS_ERROR_INVALID_PUBLIC_KEY_LENGTH);
        }

        uint8_t client_public_key_pkf[CLTLS_ENTITY_PKF_LENGTH] = {0};
        memcpy(client_public_key_pkf,
               decryption_buffer.data,
               CLTLS_ENTITY_PKF_LENGTH);

        uint8_t client_binded_identity_pka[CLTLS_BINDED_IDENTITY_PKA_LENGTH] = {0};
        BindIdentityPka(client_identity,
                        decryption_buffer.data + CLTLS_ENTITY_PKF_LENGTH,
                        client_binded_identity_pka);
        // Verify Public Key
        if (!ED25519_verify(client_binded_identity_pka,
                            CLTLS_BINDED_IDENTITY_PKA_LENGTH,
                            decryption_buffer.data +
                                CLTLS_ENTITY_PKF_LENGTH +
                                CLTLS_ENTITY_PKA_LENGTH,
                            ctx->kgc_public_key))
        {
            LogError("[%s] Client public key verification failed, is he an adversary?",
                     current_stage);
            HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
                CLTLS_ERROR_PUBLIC_KEY_VERIFY_FAILED);
        }

        // [Receive] Client Public Key Verify
        current_stage = "RECEIVE Client Public Key Verify";

        HANDSHAKE_RECEIVE(CLIENT_PUBKEY_VERIFY, false);

        ByteVecResize(&decryption_buffer, receive_remaining_length);

        if (!aead->Decrypt(CLTLS_REMAINING_HEADER(receive_buffer.data),
                           receive_remaining_length,
                           decryption_buffer.data, &decrypted_length,
                           NULL, 0,
                           client_handshake_key,
                           client_handshake_npub_iv,
                           &iv_length))
        {
            LogError("[%s] Decryption of |client_public_key_verify| failed",
                     current_stage);
            HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
                CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
        }

        if (decrypted_length != CLTLS_TRAFFIC_SIGNATURE_LENGTH)
        {
            LogError("[%s] Client traffic signature length is %zu, expected %zu",
                     current_stage,
                     decrypted_length,
                     CLTLS_TRAFFIC_SIGNATURE_LENGTH);
            HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
                CLTLS_ERROR_INVALID_TRAFFIC_SIGNATURE_LENGTH);
        }

        hash->Hash(traffic_buffer.data, traffic_buffer.size, traffic_hash);

        // Append traffic after calculating traffic hash
        ByteVecPushBackBlockFromByteVec(&traffic_buffer, &receive_buffer);

        if (!ED25519_verify(traffic_hash, hash->hash_size,
                            decryption_buffer.data,
                            client_public_key_pkf))
        {
            LogError("[%s] Client traffic signature verification failed, is there an MiTM?",
                     current_stage);
            HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
                CLTLS_ERROR_TRAFFIC_SIGNATURE_VERIFY_FAILED);
        }
    }

    // [Receive] Client Handshake Finished
    current_stage = "RECEIVE Client Handshake Finished";

    HANDSHAKE_RECEIVE(CLIENT_HANDSHAKE_FINISHED, false);

    memcpy(secret_info, "finished", 8);

    if (!HKDF_expand(finished_key, hash->hash_size,
                     md_hmac_hkdf,
                     client_secret, hash->hash_size,
                     secret_info, 8))
    {
        LogError("[%s] HKDF_expand() for |client_finished_key| failed: %s",
                 current_stage,
                 ERR_error_string(ERR_get_error(), NULL));
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    hash->Hash(traffic_buffer.data, traffic_buffer.size, traffic_hash);

    // Append traffic after calculating traffic hash
    ByteVecPushBackBlockFromByteVec(&traffic_buffer, &receive_buffer);

    if (HMAC(md_hmac_hkdf,
             finished_key, hash->hash_size,
             traffic_hash, hash->hash_size,
             verify_data, &verify_data_length) == NULL)
    {
        LogError("[%s] HMAC() for |client_verify_data| failed: %s",
                 current_stage,
                 ERR_error_string(ERR_get_error(), NULL));
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    ByteVecResize(&decryption_buffer, receive_remaining_length);

    if (!aead->Decrypt(CLTLS_REMAINING_HEADER(receive_buffer.data),
                       receive_remaining_length,
                       decryption_buffer.data, &decrypted_length,
                       NULL, 0,
                       client_handshake_key,
                       client_handshake_npub_iv,
                       &iv_length))
    {
        LogError("[%s] Decryption of |client_public_key_verify| failed",
                 current_stage);
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    if (decrypted_length != verify_data_length)
    {
        LogError("[%s] Client finished verify data length is %zu, expected %u",
                 current_stage,
                 decrypted_length,
                 verify_data_length);
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INVALID_VERIFY_DATA_LENGTH);
    }

    if (memcmp(verify_data, decryption_buffer.data, verify_data_length))
    {
        LogError("[%s] Client finished verify data verification failed, is there an attack?",
                 current_stage);
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_VERIFY_DATA_VERIFY_FAILED);
    }

    // [Server Application Keys Calc]
    current_stage = "Server Application Keys Calc";

    uint8_t master_secret[MAX_HASH_LENGTH] = {0};

    CALCULATE_HANDSHAKE_KEY;

    ByteVecResize(&send_buffer, CLTLS_COMMON_HEADER_LENGTH);
    CLTLS_SET_COMMON_HEADER(send_buffer.data, CLTLS_MSG_TYPE_HANDSHAKE_SUCCEED, 0);
    if (!TcpSend(ctx->socket_fd,
                 send_buffer.data,
                 send_buffer.size))
    {
        LogError("[%s] Failed to send HANDSHAKE_SUCCEED",
                 current_stage);
        HANDSHAKE_FREE_RETURN_FALSE;
    }

    HANDSHAKE_RECEIVE(HANDSHAKE_SUCCEED, false);

    handshake_result_ret->aead = aead;
    handshake_result_ret->iv_length = iv_length;

    ByteVecFree(&receive_buffer);
    ByteVecFree(&send_buffer);
    ByteVecFree(&traffic_buffer);
    ByteVecFree(&decryption_buffer);

    LogInfo("Handshake successful");

    return true;
}
