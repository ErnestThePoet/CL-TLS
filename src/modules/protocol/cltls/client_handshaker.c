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

    uint8_t self_ke_public_key[CLTLS_KE_PUBLIC_KEY_LENGTH] = {0};
    uint8_t self_ke_private_key[CLTLS_KE_PRIVATE_KEY_LENGTH] = {0};
    uint8_t self_ke_random[CLTLS_KE_RANDOM_LENGTH] = {0};

    GENERATE_KE_KEY_RANDOM;

    ByteVecResize(&send_buffer, CLTLS_COMMON_HEADER_LENGTH);

    ByteVecPushBack(&send_buffer, ctx->application_layer_protocol);
    ByteVecPushBackBlock(&send_buffer, ctx->client_identity, ENTITY_IDENTITY_LENGTH);
    ByteVecPushBack(&send_buffer, ctx->client_cipher_suite_set->size);
    foreach (set_CipherSuite, ctx->client_cipher_suite_set, cipher_suite)
    {
        ByteVecPushBack(&send_buffer, cipher_suite.ref->cipher_suite);
    }
    ByteVecPushBackBlock(&send_buffer, self_ke_public_key, CLTLS_KE_PUBLIC_KEY_LENGTH);
    ByteVecPushBackBlock(&send_buffer, self_ke_random, CLTLS_KE_RANDOM_LENGTH);

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

    ByteVecPushBackBlockFromByteVec(&traffic_buffer, &send_buffer);

    // [Receive] Server Hello
    const char *current_stage = "SEND Server Hello";

    HANDSHAKE_RECEIVE(SERVER_HELLO, true);

    uint8_t selected_cipher_suite = CLTLS_REMAINING_HEADER(receive_buffer.data)[0];

    if (set_CipherSuite_find(ctx->client_cipher_suite_set,
                             (CipherSuite){
                                 .cipher_suite = selected_cipher_suite}) ==
        set_CipherSuite_end(ctx->client_cipher_suite_set))
    {
        LogError("[%s] Server's chosen cipher suite is not supported",
                 current_stage);
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_SELECTED_CIPHER_SUITE_UNSUPPORTED);
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
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
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
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    if (decrypted_length != CLTLS_ENTITY_PUBLIC_KEY_LENGTH)
    {
        LogError("[%s] Server public key length is %zu, expected %zu",
                 current_stage,
                 decrypted_length,
                 CLTLS_ENTITY_PUBLIC_KEY_LENGTH);
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INVALID_PUBLIC_KEY_LENGTH);
    }

    uint8_t server_public_key_pkf[CLTLS_ENTITY_PUBLIC_KEY_PKF_LENGTH] = {0};
    memcpy(server_public_key_pkf,
           decryption_buffer.data,
           CLTLS_ENTITY_PUBLIC_KEY_PKF_LENGTH);

    uint8_t server_binded_identity_pka[CLTLS_BINDED_IDENTITY_PKA_LENGTH] = {0};
    BindIdentityPka(ctx->server_identity,
                    decryption_buffer.data + CLTLS_ENTITY_PUBLIC_KEY_PKF_LENGTH,
                    server_binded_identity_pka);
    // Verify Public Key
    if (!ED25519_verify(server_binded_identity_pka,
                        CLTLS_BINDED_IDENTITY_PKA_LENGTH,
                        decryption_buffer.data +
                            CLTLS_ENTITY_PUBLIC_KEY_PKF_LENGTH +
                            CLTLS_ENTITY_PUBLIC_KEY_PKA_LENGTH,
                        ctx->kgc_public_key))
    {
        LogError("[%s] Server public key verification failed, is he an adversary?",
                 current_stage);
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_PUBLIC_KEY_VERIFY_FAILED);
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
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    if (decrypted_length != CLTLS_TRAFFIC_SIGNATURE_LENGTH)
    {
        LogError("[%s] Server traffic signature length is %zu, expected %zu",
                 current_stage,
                 decrypted_length,
                 CLTLS_TRAFFIC_SIGNATURE_LENGTH);
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INVALID_TRAFFIC_SIGNATURE_LENGTH);
    }

    uint8_t traffic_hash[MAX_HASH_LENGTH] = {0};

    hash->Hash(traffic_buffer.data, traffic_buffer.size, traffic_hash);

    // Append traffic after calculating traffic hash
    ByteVecPushBackBlockFromByteVec(&traffic_buffer, &receive_buffer);

    if (!ED25519_verify(traffic_hash, hash->hash_size,
                        decryption_buffer.data,
                        server_public_key_pkf))
    {
        LogError("[%s] Server traffic signature verification failed, is there an MiTM?",
                 current_stage);
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_TRAFFIC_SIGNATURE_VERIFY_FAILED);
    }

    const bool should_request_public_key =
        ShouldRequestClientPublicKey(ctx->application_layer_protocol);

    if (should_request_public_key)
    {
        // [Receive] Server Public Key Request
        current_stage = "RECEIVE Server Public Key Request";

        HANDSHAKE_RECEIVE(SERVER_PUBKEY_REQUEST, true);
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
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
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
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
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
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    if (decrypted_length != verify_data_length)
    {
        LogError("[%s] Server finished verify data length is %zu, expected %u",
                 current_stage,
                 decrypted_length,
                 verify_data_length);
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_INVALID_VERIFY_DATA_LENGTH);
    }

    if (memcmp(verify_data, decryption_buffer.data, verify_data_length))
    {
        LogError("[%s] Server finished verify data verification failed, is there an attack?",
                 current_stage);
        SEND_ERROR_STOP_NOTIFY(CLTLS_ERROR_VERIFY_DATA_VERIFY_FAILED);
    }

    return true;
}