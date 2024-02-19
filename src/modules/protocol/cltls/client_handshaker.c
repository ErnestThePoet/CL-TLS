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

    return true;
}