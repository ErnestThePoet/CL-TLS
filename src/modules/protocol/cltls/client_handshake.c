#include "client_handshake.h"

bool ClientHandshake(const ClientHandshakeCtx *ctx,
                     HandshakeResult *handshake_result_ret)
{
    clock_t start_time = clock();

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

    uint8_t self_ke_public_key[CLTLS_KE_PUBLIC_KEY_LENGTH] = {0};
    uint8_t self_ke_private_key[CLTLS_KE_PRIVATE_KEY_LENGTH] = {0};
    uint8_t self_handshake_random[CLTLS_HANDSHAKE_RANDOM_LENGTH] = {0};

    GENERATE_KE_KEY_RANDOM;

    ByteVecResize(&send_buffer, CLTLS_COMMON_HEADER_LENGTH);

    ByteVecPushBack(&send_buffer, ctx->application_layer_protocol);
    ByteVecPushBackBlock(&send_buffer, ctx->client_identity, ENTITY_IDENTITY_LENGTH);
    ByteVecPushBack(&send_buffer, ctx->client_cipher_suite_set->size);
    foreach (set_CipherSuite, ctx->client_cipher_suite_set, cipher_suite)
    {
        ByteVecPushBack(&send_buffer, cipher_suite.ref->cipher_suite);
    }
    ByteVecPushBackBlock(&send_buffer,
                         self_ke_public_key,
                         CLTLS_KE_PUBLIC_KEY_LENGTH);
    ByteVecPushBackBlock(&send_buffer,
                         self_handshake_random,
                         CLTLS_HANDSHAKE_RANDOM_LENGTH);

    CLTLS_SET_COMMON_HEADER(send_buffer.data,
                            CLTLS_MSG_TYPE_CLIENT_HELLO,
                            send_buffer.size - CLTLS_COMMON_HEADER_LENGTH);

    if (!TcpSend(ctx->socket_fd,
                 send_buffer.data,
                 send_buffer.size))
    {
        LogError("[%s] Failed to send CLIENT_HELLO",
                 current_stage);
        HANDSHAKE_FREE_RETURN_FALSE;
    }

    ByteVecPushBackBlockFromByteVec(&traffic_buffer, &send_buffer);

    // [Receive] Server Hello
    current_stage = "RECEIVE Server Hello";

    HANDSHAKE_RECEIVE(SERVER_HELLO, true);

    uint8_t selected_cipher_suite = CLTLS_REMAINING_HEADER(receive_buffer.data)[0];

    if (set_CipherSuite_find(ctx->client_cipher_suite_set,
                             (CipherSuite){
                                 .cipher_suite = selected_cipher_suite}) ==
        set_CipherSuite_end(ctx->client_cipher_suite_set))
    {
        LogError("[%s] Server's chosen cipher suite is not supported",
                 current_stage);
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_SELECTED_CIPHER_SUITE_UNSUPPORTED);
    }

    const HashScheme *hash = NULL;
    const AeadScheme *aead = NULL;
    const EVP_MD *md_hmac_hkdf = NULL;
    GetCryptoSchemes(selected_cipher_suite, &hash, &aead, &md_hmac_hkdf);

    // [Client Handshake Keys Calc]
    current_stage = "Client Handshake Keys Calc";

    uint8_t shared_secret[X25519_SHARED_KEY_LEN] = {0};
    if (!X25519(shared_secret,
                self_ke_private_key,
                CLTLS_REMAINING_HEADER(receive_buffer.data) +
                    CLTLS_CIPHER_SUITE_LENGTH))
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

    const bool should_send_public_key =
        ShouldRequestClientPublicKey(ctx->application_layer_protocol);

    if (should_send_public_key)
    {
        // [Receive] Server Public Key Request
        current_stage = "RECEIVE Server Public Key Request";

        HANDSHAKE_RECEIVE(SERVER_PUBKEY_REQUEST, true);
    }

    // [Receive] Server Public Key
    current_stage = "RECEIVE Server Public Key";

    HANDSHAKE_RECEIVE(SERVER_PUBKEY, true);

    size_t encrypted_length = 0;
    size_t decrypted_length = 0;
    // Used for AES only
    size_t iv_length = aead->npub_iv_size;

    ByteVecResize(&decryption_buffer, receive_remaining_length);

    if (!aead->Decrypt(CLTLS_REMAINING_HEADER(receive_buffer.data),
                       receive_remaining_length,
                       decryption_buffer.data, &decrypted_length,
                       NULL, 0,
                       server_handshake_key,
                       server_handshake_npub_iv,
                       &iv_length))
    {
        LogError("[%s] Decryption of |server_public_key| failed",
                 current_stage);
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    if (decrypted_length != CLTLS_ENTITY_PUBLIC_KEY_LENGTH)
    {
        LogError("[%s] Server public key length is %zu, expected %zu",
                 current_stage,
                 decrypted_length,
                 CLTLS_ENTITY_PUBLIC_KEY_LENGTH);
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INVALID_PUBLIC_KEY_LENGTH);
    }

    uint8_t server_public_key[CLTLS_ENTITY_PUBLIC_KEY_LENGTH] = {0};
    memcpy(server_public_key,
           decryption_buffer.data,
           CLTLS_ENTITY_PUBLIC_KEY_LENGTH);

    uint8_t server_id_pkab[CLTLS_ID_PKAB_LENGTH] = {0};
    BindIdPkaPkb(ctx->server_identity,
                 decryption_buffer.data,
                 decryption_buffer.data + CLTLS_ENTITY_PKA_LENGTH,
                 server_id_pkab);
    // Verify Public Key
    if (!CltlsVerify(server_id_pkab,
                     CLTLS_ID_PKAB_LENGTH,
                     decryption_buffer.data +
                         CLTLS_ENTITY_PKA_LENGTH +
                         CLTLS_ENTITY_PKB_LENGTH,
                     ctx->kgc_public_key))
    {
        LogError("[%s] Server public key verification failed, is he an adversary?",
                 current_stage);
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_PUBLIC_KEY_VERIFY_FAILED);
    }

    // [Receive] Server Public Key Verify
    current_stage = "RECEIVE Server Public Key Verify";

    HANDSHAKE_RECEIVE(SERVER_PUBKEY_VERIFY, false);

    ByteVecResize(&decryption_buffer, receive_remaining_length);

    if (!aead->Decrypt(CLTLS_REMAINING_HEADER(receive_buffer.data),
                       receive_remaining_length,
                       decryption_buffer.data, &decrypted_length,
                       NULL, 0,
                       server_handshake_key,
                       server_handshake_npub_iv,
                       &iv_length))
    {
        LogError("[%s] Decryption of |server_public_key_verify| failed",
                 current_stage);
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    if (decrypted_length != CLTLS_TRAFFIC_SIGNATURE_LENGTH)
    {
        LogError("[%s] Server traffic signature length is %zu, expected %zu",
                 current_stage,
                 decrypted_length,
                 CLTLS_TRAFFIC_SIGNATURE_LENGTH);
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INVALID_TRAFFIC_SIGNATURE_LENGTH);
    }

    uint8_t traffic_hash[MAX_HASH_LENGTH] = {0};
    uint8_t traffic_signature[CLTLS_TRAFFIC_SIGNATURE_LENGTH] = {0};

    hash->Hash(traffic_buffer.data, traffic_buffer.size, traffic_hash);

    // Append traffic after calculating traffic hash
    ByteVecPushBackBlockFromByteVec(&traffic_buffer, &receive_buffer);

    if (!CltlsVerify(traffic_hash, hash->hash_size,
                     decryption_buffer.data,
                     server_public_key))
    {
        LogError("[%s] Server traffic signature verification failed, is there an MiTM?",
                 current_stage);
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_TRAFFIC_SIGNATURE_VERIFY_FAILED);
    }

    // [Receive] Server Handshake Finished
    current_stage = "RECEIVE Server Handshake Finished";

    HANDSHAKE_RECEIVE(SERVER_HANDSHAKE_FINISHED, false);

    uint8_t *finished_key = derived_secret;
    uint8_t verify_data[MAX_HASH_LENGTH] = {0};
    unsigned int verify_data_length = 0;

    memcpy(secret_info, "finished", 8);

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

    // Append traffic after calculating traffic hash
    ByteVecPushBackBlockFromByteVec(&traffic_buffer, &receive_buffer);

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

    ByteVecResize(&decryption_buffer, receive_remaining_length);

    if (!aead->Decrypt(CLTLS_REMAINING_HEADER(receive_buffer.data),
                       receive_remaining_length,
                       decryption_buffer.data, &decrypted_length,
                       NULL, 0,
                       server_handshake_key,
                       server_handshake_npub_iv,
                       &iv_length))
    {
        LogError("[%s] Decryption of |server_public_key_verify| failed",
                 current_stage);
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    if (decrypted_length != verify_data_length)
    {
        LogError("[%s] Server finished verify data length is %zu, expected %u",
                 current_stage,
                 decrypted_length,
                 verify_data_length);
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INVALID_VERIFY_DATA_LENGTH);
    }

    if (memcmp(verify_data, decryption_buffer.data, verify_data_length))
    {
        LogError("[%s] Server finished verify data verification failed, is there an attack?",
                 current_stage);
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_VERIFY_DATA_VERIFY_FAILED);
    }

    if (should_send_public_key)
    {
        // [Send] Client Public Key
        current_stage = "SEND Client Public Key";

        // Max encrypted size is plain text size + max enc block size
        ByteVecResize(&send_buffer,
                      CLTLS_COMMON_HEADER_LENGTH +
                          CLTLS_ENTITY_PUBLIC_KEY_LENGTH +
                          MAX_ENC_EXTRA_SIZE);

        if (!aead->Encrypt(ctx->client_public_key, CLTLS_ENTITY_PUBLIC_KEY_LENGTH,
                           CLTLS_REMAINING_HEADER(send_buffer.data), &encrypted_length,
                           NULL, 0,
                           client_handshake_key,
                           client_handshake_npub_iv,
                           &iv_length))
        {
            LogError("[%s] Encryption of |client_public_key| failed",
                     current_stage);
            HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
                CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
        }

        ByteVecResize(&send_buffer, CLTLS_COMMON_HEADER_LENGTH + encrypted_length);

        CLTLS_SET_COMMON_HEADER(send_buffer.data,
                                CLTLS_MSG_TYPE_CLIENT_PUBKEY,
                                encrypted_length);

        if (!TcpSend(ctx->socket_fd,
                     send_buffer.data,
                     send_buffer.size))
        {
            LogError("[%s] Failed to send CLIENT_PUBKEY",
                     current_stage);
            HANDSHAKE_FREE_RETURN_FALSE;
        }

        ByteVecPushBackBlockFromByteVec(&traffic_buffer, &send_buffer);

        // [Send] Client Public Key Verify
        current_stage = "SEND Client Public Key Verify";

        hash->Hash(traffic_buffer.data, traffic_buffer.size, traffic_hash);

        if (!CltlsSign(traffic_signature,
                       traffic_hash,
                       hash->hash_size,
                       ctx->client_private_key))
        {
            LogError("[%s] CltlsSign() for |traffic_hash| failed: %s",
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
                           client_handshake_key,
                           client_handshake_npub_iv,
                           &iv_length))
        {
            LogError("[%s] Encryption of |traffic_signature| failed",
                     current_stage);
            HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
                CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
        }

        ByteVecResize(&send_buffer, CLTLS_COMMON_HEADER_LENGTH + encrypted_length);

        CLTLS_SET_COMMON_HEADER(send_buffer.data,
                                CLTLS_MSG_TYPE_CLIENT_PUBKEY_VERIFY,
                                encrypted_length);

        if (!TcpSend(ctx->socket_fd,
                     send_buffer.data,
                     send_buffer.size))
        {
            LogError("[%s] Failed to send CLIENT_PUBKEY_VERIFY",
                     current_stage);
            HANDSHAKE_FREE_RETURN_FALSE;
        }

        ByteVecPushBackBlockFromByteVec(&traffic_buffer, &send_buffer);
    }

    // [Send] Client Handshake Finished
    current_stage = "SEND Client Handshake Finished";

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

    ByteVecResize(&send_buffer,
                  CLTLS_COMMON_HEADER_LENGTH +
                      verify_data_length +
                      MAX_ENC_EXTRA_SIZE);

    if (!aead->Encrypt(verify_data, verify_data_length,
                       CLTLS_REMAINING_HEADER(send_buffer.data), &encrypted_length,
                       NULL, 0,
                       client_handshake_key,
                       client_handshake_npub_iv,
                       &iv_length))
    {
        LogError("[%s] Encryption of |client_verify_data| failed",
                 current_stage);
        HANDSHAKE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    ByteVecResize(&send_buffer, CLTLS_COMMON_HEADER_LENGTH + encrypted_length);

    CLTLS_SET_COMMON_HEADER(send_buffer.data,
                            CLTLS_MSG_TYPE_CLIENT_HANDSHAKE_FINISHED,
                            encrypted_length);

    if (!TcpSend(ctx->socket_fd,
                 send_buffer.data,
                 send_buffer.size))
    {
        LogError("[%s] Failed to send CLIENT_HANDSHAKE_FINISHED",
                 current_stage);
        HANDSHAKE_FREE_RETURN_FALSE;
    }

    ByteVecPushBackBlockFromByteVec(&traffic_buffer, &send_buffer);

    // [Client Application Keys Calc]
    current_stage = "Client Application Keys Calc";

    uint8_t master_secret[MAX_HASH_LENGTH] = {0};

    CALCULATE_APPLICATION_KEY;

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

    handshake_result_ret->aead = (AeadScheme *)aead;
    handshake_result_ret->iv_length = iv_length;

    ByteVecFree(&receive_buffer);
    ByteVecFree(&send_buffer);
    ByteVecFree(&traffic_buffer);
    ByteVecFree(&decryption_buffer);

    clock_t end_time = clock();

    LogSuccess("Client handshake successful");

    if (kPrintTiming)
    {
        LogTiming("Client handshake finished in %.03fms",
                  MS(end_time - start_time));
    }

    return true;
}