#include "server_register.h"

bool ServerRegister()
{
    ByteVec send_buffer;
    ByteVec receive_buffer;

    ByteVecInitWithCapacity(&send_buffer, INITIAL_SOCKET_BUFFER_CAPACITY);
    ByteVecInitWithCapacity(&receive_buffer, INITIAL_SOCKET_BUFFER_CAPACITY);

    BIGNUM *pka_bn = BN_new();
    if (pka_bn == NULL)
    {
        LogError("Memory allocation for |pka_bn| failed");
        exit(EXIT_FAILURE);
    }

    BIGNUM *ska_bn = BN_new();
    if (ska_bn == NULL)
    {
        LogError("Memory allocation for |ska_bn| failed");
        BN_free(pka_bn);
        exit(EXIT_FAILURE);
    }

    if (!BN_rand(pka_bn,
                 CLTLS_ENTITY_PKB_LENGTH * 8,
                 BN_RAND_TOP_ANY,
                 BN_RAND_BOTTOM_ANY))
    {
        LogError("BN_rand() for |pka_bn| failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        BN_free(pka_bn);
        BN_free(ska_bn);
        SERVER_REGISTER_FREE_RETURN_FALSE;
    }

    if (!BN_rand(ska_bn,
                 CLTLS_ENTITY_SKA_LENGTH * 8,
                 BN_RAND_TOP_ANY,
                 BN_RAND_BOTTOM_ANY))
    {
        LogError("BN_rand() for |ska_bn| failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        BN_free(pka_bn);
        BN_free(ska_bn);
        SERVER_REGISTER_FREE_RETURN_FALSE;
    }

    uint8_t pka[CLTLS_ENTITY_PKB_LENGTH] = {0};
    uint8_t sign_ska[CLTLS_ENTITY_ID_PKAB_SIGNATURE_LENGTH +
                     CLTLS_ENTITY_SKA_LENGTH] = {0};

    if (!BN_bn2bin_padded(pka,
                          CLTLS_ENTITY_PKB_LENGTH,
                          pka_bn))
    {
        LogError("BN_bn2bin_padded() for |pka| failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        BN_free(pka_bn);
        BN_free(ska_bn);
        SERVER_REGISTER_FREE_RETURN_FALSE;
    }

    if (!BN_bn2bin_padded(sign_ska + CLTLS_ENTITY_ID_PKAB_SIGNATURE_LENGTH,
                          CLTLS_ENTITY_SKA_LENGTH,
                          ska_bn))
    {
        LogError("BN_bn2bin_padded() for |sign_ska| failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        BN_free(pka_bn);
        BN_free(ska_bn);
        SERVER_REGISTER_FREE_RETURN_FALSE;
    }

    BN_free(pka_bn);
    BN_free(ska_bn);

    ByteVecResize(&send_buffer, KGC_REGISTER_REQUEST_SERVER_HEADER_LENGTH);

    send_buffer.data[0] = KGC_MSG_TYPE_REGISTER_REQUEST;
    send_buffer.data[KGC_MSG_TYPE_LENGTH] = KGC_ENTITY_TYPE_SERVER;
    memcpy(send_buffer.data +
               KGC_MSG_TYPE_LENGTH +
               KGC_ENTITY_TYPE_LENGTH,
           kServerIdentity,
           ENTITY_IDENTITY_LENGTH);
    memcpy(send_buffer.data +
               KGC_MSG_TYPE_LENGTH +
               KGC_ENTITY_TYPE_LENGTH +
               ENTITY_IDENTITY_LENGTH,
           pka,
           CLTLS_ENTITY_PKB_LENGTH);

    IdIp kgc_idip_key;
    memcpy(kgc_idip_key.id, kKgcIdentity, ENTITY_IDENTITY_LENGTH);
    set_IdIp_node *kgc_idip = set_IdIp_find(&kServerIdIpTable, kgc_idip_key);
    if (kgc_idip == set_IdIp_end(&kServerIdIpTable))
    {
        LogError("KGC ID not in ID/IP table");
        SERVER_REGISTER_FREE_RETURN_FALSE;
    }

    int kgc_socket_fd = 0;
    if (!TcpConnectToServer(kgc_idip->key.ip,
                            kKgcListenPort,
                            &kgc_socket_fd))
    {
        LogError("Cannot connect to KGC");
        SERVER_REGISTER_FREE_RETURN_FALSE;
    }

    ClientHandshakeCtx client_handshake_ctx = {
        .socket_fd = kgc_socket_fd,
        .application_layer_protocol = CLTLS_PROTOCOL_KGC_REGISTER_REQUEST,
        .client_cipher_suite_set = &kServerCipherSuiteSet,
        .client_identity = kServerIdentity,
        .client_private_key = NULL, // Empty
        .client_public_key = NULL,  // Empty
        .kgc_public_key = kKgcPublicKey,
        .server_identity = kKgcIdentity};

    HandshakeResult client_handshake_result;

    if (!ClientHandshake(&client_handshake_ctx,
                         &client_handshake_result))
    {
        LogError("CL-TLS handshake failed with KGC");
        SERVER_REGISTER_CLOSE_FREE_RETURN_FALSE;
    }

    if (!SendApplicationData(kgc_socket_fd,
                             &client_handshake_result,
                             true,
                             &send_buffer))
    {
        SERVER_REGISTER_CLOSE_FREE_RETURN_FALSE;
    }

    if (!ReceiveApplicationData(kgc_socket_fd,
                                &client_handshake_result,
                                true,
                                &receive_buffer))
    {
        SERVER_REGISTER_CLOSE_FREE_RETURN_FALSE;
    }

    TcpClose(kgc_socket_fd);

    if (receive_buffer.data[0] != KGC_MSG_TYPE_RESIGTER_RESPONSE)
    {
        LogError("Unexpected message type received from "
                 "KGC; RESIGTER_RESPONSE expected");
        SERVER_REGISTER_FREE_RETURN_FALSE;
    }

    if (receive_buffer.data[KGC_MSG_TYPE_LENGTH] == KGC_REGISTER_STATUS_FAILURE)
    {
        LogError("KGC reports register failure");
        SERVER_REGISTER_FREE_RETURN_FALSE;
    }

    memcpy(sign_ska,
           receive_buffer.data + KGC_MSG_TYPE_LENGTH + KGC_ENTITY_TYPE_LENGTH,
           CLTLS_ENTITY_ID_PKAB_SIGNATURE_LENGTH);

    uint8_t keypair_seed[32] = {0};
    uint8_t hkdf_salt[32] = {0};

    if (!HKDF(keypair_seed, 32,
              EVP_AsconHash(),
              sign_ska,
              CLTLS_ENTITY_ID_PKAB_SIGNATURE_LENGTH + CLTLS_ENTITY_SKA_LENGTH,
              hkdf_salt, 32,
              (const uint8_t *)"Server Keypair Seed", 19))
    {
        LogError("HKDF() for |keypair_seed| failed: %s",
                 ERR_error_string(ERR_get_error(), NULL));
        SERVER_REGISTER_FREE_RETURN_FALSE;
    }

    // pre allocate space for full public key
    uint8_t public_key[CLTLS_ENTITY_PUBLIC_KEY_LENGTH] = {0};
    uint8_t private_key[CLTLS_ENTITY_PRIVATE_KEY_LENGTH] = {0};
    ED25519_keypair_from_seed(public_key, private_key, keypair_seed);

    memcpy(public_key + CLTLS_ENTITY_PKA_LENGTH,
           pka,
           CLTLS_ENTITY_PKB_LENGTH);
    memcpy(public_key + CLTLS_ENTITY_PKA_LENGTH + CLTLS_ENTITY_PKB_LENGTH,
           sign_ska,
           CLTLS_ENTITY_ID_PKAB_SIGNATURE_LENGTH);

    FILE *public_key_file = fopen(kServerPublicKeyPath, "wb");
    if (public_key_file == NULL)
    {
        LogError("Failed to open public key file %s for writing",
                 kServerPublicKeyPath);
        SERVER_REGISTER_FREE_RETURN_FALSE;
    }

    if (fwrite(public_key, 1, CLTLS_ENTITY_PUBLIC_KEY_LENGTH, public_key_file) !=
        CLTLS_ENTITY_PUBLIC_KEY_LENGTH)
    {
        LogError("Failed to write public key into file %s",
                 kServerPublicKeyPath);
        fclose(public_key_file);
        SERVER_REGISTER_FREE_RETURN_FALSE;
    }

    fclose(public_key_file);

    FILE *private_key_file = fopen(kServerPrivateKeyPath, "wb");
    if (private_key_file == NULL)
    {
        LogError("Failed to open private key file %s for writing",
                 kServerPrivateKeyPath);
        SERVER_REGISTER_FREE_RETURN_FALSE;
    }

    if (fwrite(private_key, 1, CLTLS_ENTITY_PRIVATE_KEY_LENGTH, private_key_file) !=
        CLTLS_ENTITY_PRIVATE_KEY_LENGTH)
    {
        LogError("Failed to write private key into file %s",
                 kServerPrivateKeyPath);
        fclose(private_key_file);
        SERVER_REGISTER_FREE_RETURN_FALSE;
    }

    fclose(private_key_file);

    LogSuccess("Successfully resigtered server");

    ByteVecFree(&send_buffer);
    ByteVecFree(&receive_buffer);
    return true;
}