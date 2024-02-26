#include "client_register.h"

bool ClientRegister(const char *belonging_servers_file_path)
{
    ByteVec send_buffer;
    ByteVec receive_buffer;

    ByteVecInitWithCapacity(&send_buffer, INITIAL_SOCKET_BUFFER_CAPACITY);
    ByteVecInitWithCapacity(&receive_buffer, INITIAL_SOCKET_BUFFER_CAPACITY);

    const char *current_stage = "Register Client";

    BIGNUM *pka_bn = BN_new();
    if (pka_bn == NULL)
    {
        LogError("[%s] Memory allocation for |pka_bn| failed",
                 current_stage);
        exit(EXIT_FAILURE);
    }

    BIGNUM *ska_bn = BN_new();
    if (ska_bn == NULL)
    {
        LogError("[%s] Memory allocation for |ska_bn| failed",
                 current_stage);
        exit(EXIT_FAILURE);
    }

    if (!BN_rand(pka_bn,
                 CLTLS_ENTITY_PKA_LENGTH * 8,
                 BN_RAND_TOP_ANY,
                 BN_RAND_BOTTOM_ANY))
    {
        LogError("[%s] BN_rand() for |pka_bn| failed: %s",
                 current_stage,
                 ERR_error_string(ERR_get_error(), NULL));
        BN_free(pka_bn);
        BN_free(ska_bn);
        CLIENT_REGISTER_FREE_RETURN_FALSE;
    }

    if (!BN_rand(ska_bn,
                 CLTLS_ENTITY_SKA_LENGTH * 8,
                 BN_RAND_TOP_ANY,
                 BN_RAND_BOTTOM_ANY))
    {
        LogError("[%s] BN_rand() for |ska_bn| failed: %s",
                 current_stage,
                 ERR_error_string(ERR_get_error(), NULL));
        BN_free(pka_bn);
        BN_free(ska_bn);
        CLIENT_REGISTER_FREE_RETURN_FALSE;
    }

    uint8_t pka[CLTLS_ENTITY_PKA_LENGTH] = {0};
    uint8_t sign_ska[CLTLS_ENTITY_PKA_ID_SIGNATURE_LENGTH +
                     CLTLS_ENTITY_SKA_LENGTH] = {0};

    if (!BN_bn2bin_padded(pka,
                          CLTLS_ENTITY_PKA_LENGTH,
                          pka_bn))
    {
        LogError("[%s] BN_bn2bin_padded() for |pka| failed: %s",
                 current_stage,
                 ERR_error_string(ERR_get_error(), NULL));
        BN_free(pka_bn);
        BN_free(ska_bn);
        CLIENT_REGISTER_FREE_RETURN_FALSE;
    }

    if (!BN_bn2bin_padded(sign_ska + CLTLS_ENTITY_PKA_ID_SIGNATURE_LENGTH,
                          CLTLS_ENTITY_SKA_LENGTH,
                          ska_bn))
    {
        LogError("[%s] BN_bn2bin_padded() for |sign_ska| failed: %s",
                 current_stage,
                 ERR_error_string(ERR_get_error(), NULL));
        BN_free(pka_bn);
        BN_free(ska_bn);
        CLIENT_REGISTER_FREE_RETURN_FALSE;
    }

    BN_free(pka_bn);
    BN_free(ska_bn);

    ByteVecResize(&send_buffer, KGC_REGISTER_REQUEST_CLIENT_FIXED_HEADER_LENGTH);

    send_buffer.data[0] = KGC_MSG_TYPE_REGISTER_REQUEST;
    send_buffer.data[KGC_MSG_TYPE_LENGTH] = KGC_ENTITY_TYPE_CLIENT;
    memcpy(send_buffer.data +
               KGC_MSG_TYPE_LENGTH +
               KGC_ENTITY_TYPE_LENGTH,
           kClientIdentity,
           ENTITY_IDENTITY_LENGTH);
    memcpy(send_buffer.data +
               KGC_MSG_TYPE_LENGTH +
               KGC_ENTITY_TYPE_LENGTH +
               ENTITY_IDENTITY_LENGTH,
           pka,
           CLTLS_ENTITY_PKA_LENGTH);

    FILE *belonging_servers_fp = fopen(belonging_servers_file_path, "r");
    if (belonging_servers_fp == NULL)
    {
        LogError("[%s] Failed to open belonging servers file: %s",
                 current_stage,
                 belonging_servers_file_path);
        CLIENT_REGISTER_FREE_RETURN_FALSE;
    }

    uint16_t belonging_server_count = 0;

    while (true)
    {
        uint8_t current_id[ENTITY_IDENTITY_LENGTH] = {0};
        uint16_t current_port = 0;

        int read_result = fscanf(belonging_servers_fp, "%02hhX", current_id);
        if (read_result == EOF)
        {
            break;
        }

        if (read_result != 1)
        {
            LogError("Error loading belonging servers file: invalid identity value");
            fclose(belonging_servers_fp);
            CLIENT_REGISTER_FREE_RETURN_FALSE;
        }

        for (int i = 0; i < ENTITY_IDENTITY_LENGTH - 1; i++)
        {
            if (fscanf(belonging_servers_fp, "%02hhX", current_id + 1 + i) != 1)
            {
                LogError("Error loading belonging servers file: invalid identity value");
                fclose(belonging_servers_fp);
                CLIENT_REGISTER_FREE_RETURN_FALSE;
            }
        }

        if (fscanf(belonging_servers_fp, "%hu", &current_port) != 1)
        {
            LogError("Error loading belonging servers file: invalid port value");
            fclose(belonging_servers_fp);
            CLIENT_REGISTER_FREE_RETURN_FALSE;
        }

        current_port = htons(current_port);

        ByteVecPushBackBlock(&send_buffer, current_id, ENTITY_IDENTITY_LENGTH);
        ByteVecPushBackBlock(&send_buffer, &current_port, 2);

        belonging_server_count++;
    }

    fclose(belonging_servers_fp);

    belonging_server_count = htons(belonging_server_count);
    *((uint16_t *)(send_buffer.data +
                   KGC_REGISTER_REQUEST_CLIENT_FIXED_HEADER_LENGTH -
                   KGC_BELONGING_SERVER_COUNT_LENGTH)) = belonging_server_count;

    IdIp kgc_idip_key;
    memcpy(kgc_idip_key.id, kKgcIdentity, ENTITY_IDENTITY_LENGTH);
    set_IdIp_node *kgc_idip = set_IdIp_find(&kClientIdIpTable, kgc_idip_key);
    if (kgc_idip == set_IdIp_end(&kClientIdIpTable))
    {
        LogError("[%s] KGC ID not in ID/IP table", current_stage);
        CLIENT_REGISTER_FREE_RETURN_FALSE;
    }

    int kgc_socket_fd = 0;
    if (!TcpConnectToServer(kgc_idip->key.ip,
                            kKgcListenPort,
                            &kgc_socket_fd))
    {
        LogError("[%s] Cannot connect to KGC: %s", current_stage, STR_ERRNO);
        CLIENT_REGISTER_FREE_RETURN_FALSE;
    }

    ClientHandshakeCtx client_handshake_ctx = {
        .socket_fd = kgc_socket_fd,
        .application_layer_protocol = CLTLS_PROTOCOL_KGC_REGISTER_REQUEST,
        .client_cipher_suite_set = &kClientCipherSuiteSet,
        .client_identity = kClientIdentity,
        .client_private_key = kClientPrivateKey, // Empty
        .client_public_key = kClientPublicKey,   // Empty
        .kgc_public_key = kKgcPublicKey,
        .client_identity = kKgcIdentity};

    HandshakeResult client_handshake_result;

    if (!ClientHandshake(&client_handshake_ctx,
                         &client_handshake_result))
    {
        LogError("[%s] CL-TLS handshake failed with KGC",
                 current_stage);
        CLIENT_REGISTER_CLOSE_FREE_RETURN_FALSE;
    }

    if (!SendApplicationData(kgc_socket_fd,
                             &client_handshake_result,
                             true,
                             &send_buffer))
    {
        CLIENT_REGISTER_CLOSE_FREE_RETURN_FALSE;
    }

    if (!ReceiveApplicationData(kgc_socket_fd,
                                &client_handshake_result,
                                true,
                                &receive_buffer))
    {
        CLIENT_REGISTER_CLOSE_FREE_RETURN_FALSE;
    }

    TcpClose(kgc_socket_fd);

    if (receive_buffer.data[0] != KGC_MSG_TYPE_RESIGTER_RESPONSE)
    {
        LogError("[%s] Unexpected message type received from "
                 "KGC; RESIGTER_RESPONSE expected",
                 current_stage);
        CLIENT_REGISTER_FREE_RETURN_FALSE;
    }

    if (receive_buffer.data[KGC_MSG_TYPE_LENGTH] == KGC_REGISTER_STATUS_FAILURE)
    {
        LogError("[%s] KGC reports register failure", current_stage);
        CLIENT_REGISTER_FREE_RETURN_FALSE;
    }

    memcpy(sign_ska,
           receive_buffer.data + KGC_MSG_TYPE_LENGTH + KGC_ENTITY_TYPE_LENGTH,
           CLTLS_ENTITY_PKA_ID_SIGNATURE_LENGTH);

    uint8_t keypair_seed[32] = {0};
    uint8_t hkdf_salt[32] = {0};

    if (!HKDF(keypair_seed, 32,
              EVP_sha256(),
              sign_ska,
              CLTLS_ENTITY_PKA_ID_SIGNATURE_LENGTH + CLTLS_ENTITY_SKA_LENGTH,
              hkdf_salt, 32,
              "Client Keypair Seed", 19))
    {
        LogError("[%s] HKDF() for |keypair_seed| failed: %s",
                 current_stage,
                 ERR_error_string(ERR_get_error(), NULL));
        CLIENT_REGISTER_FREE_RETURN_FALSE;
    }

    uint8_t public_key[CLTLS_ENTITY_PUBLIC_KEY_LENGTH] = {0};
    uint8_t private_key[CLTLS_ENTITY_PRIVATE_KEY_LENGTH] = {0};
    ED25519_keypair_from_seed(public_key, private_key, keypair_seed);

    memcpy(public_key + CLTLS_ENTITY_PKF_LENGTH,
           pka,
           CLTLS_ENTITY_PKA_LENGTH);
    memcpy(public_key + CLTLS_ENTITY_PKF_LENGTH + CLTLS_ENTITY_PKA_LENGTH,
           sign_ska,
           CLTLS_ENTITY_PKA_ID_SIGNATURE_LENGTH);

    FILE *public_key_file = fopen(kClientPublicKeyPath, "wb");
    if (public_key_file == NULL)
    {
        LogError("[%s] Failed to open public key file %s for writing",
                 current_stage,
                 kClientPublicKeyPath);
        CLIENT_REGISTER_FREE_RETURN_FALSE;
    }

    if (fwrite(public_key, 1, CLTLS_ENTITY_PUBLIC_KEY_LENGTH, public_key_file) !=
        CLTLS_ENTITY_PUBLIC_KEY_LENGTH)
    {
        LogError("[%s] Failed to write public key into file %s",
                 current_stage,
                 kClientPublicKeyPath);
        fclose(public_key_file);
        CLIENT_REGISTER_FREE_RETURN_FALSE;
    }

    fclose(public_key_file);

    FILE *private_key_file = fopen(kClientPrivateKeyPath, "wb");
    if (private_key_file == NULL)
    {
        LogError("[%s] Failed to open private key file %s for writing",
                 current_stage,
                 kClientPrivateKeyPath);
        CLIENT_REGISTER_FREE_RETURN_FALSE;
    }

    if (fwrite(private_key, 1, CLTLS_ENTITY_PRIVATE_KEY_LENGTH, private_key_file) !=
        CLTLS_ENTITY_PRIVATE_KEY_LENGTH)
    {
        LogError("[%s] Failed to write private key into file %s",
                 current_stage,
                 kClientPrivateKeyPath);
        fclose(private_key_file);
        CLIENT_REGISTER_FREE_RETURN_FALSE;
    }

    fclose(private_key_file);

    LogInfo("Successfully resigtered client");

    ByteVecFree(&send_buffer);
    ByteVecFree(&receive_buffer);
    return true;
}