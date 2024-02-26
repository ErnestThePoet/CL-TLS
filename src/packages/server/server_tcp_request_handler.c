#include "server_tcp_request_handler.h"

static bool KgcServe(const int socket_fd,
                     const HandshakeResult *handshake_result)
{
    ByteVec send_buffer;
    ByteVec receive_buffer;

    ByteVecInitWithCapacity(&send_buffer, INITIAL_SOCKET_BUFFER_CAPACITY);
    ByteVecInitWithCapacity(&receive_buffer, INITIAL_SOCKET_BUFFER_CAPACITY);

    const char *current_stage = "KGC Serve";

    if (!ReceiveApplicationData(socket_fd,
                                handshake_result,
                                false,
                                &receive_buffer))
    {
        KGC_SERVE_FREE_RETURN_FALSE;
    }

    if (receive_buffer.data[0] != KGC_MSG_TYPE_REGISTER_REQUEST)
    {
        LogError("[%s] Unexpected KGC message type; "
                 "KGC_MSG_TYPE_REGISTER_REQUEST expected",
                 current_stage);
        KGC_SERVE_SEND_REGISTER_RESPONSE_FAILURE;
    }

    uint8_t *client_identity = receive_buffer.data +
                               KGC_MSG_TYPE_LENGTH +
                               KGC_ENTITY_TYPE_LENGTH;

    uint8_t binded_id_pka[CLTLS_BINDED_IDENTITY_PKA_LENGTH] = {0};

    BindIdentityPka(client_identity,
                    receive_buffer.data +
                        KGC_MSG_TYPE_LENGTH +
                        KGC_ENTITY_TYPE_LENGTH +
                        ENTITY_IDENTITY_LENGTH,
                    binded_id_pka);

    uint8_t binded_id_pka_signature[CLTLS_ENTITY_PKA_ID_SIGNATURE_LENGTH] = {0};

    if (!ED25519_sign(binded_id_pka_signature,
                      binded_id_pka, CLTLS_BINDED_IDENTITY_PKA_LENGTH,
                      kServerPrivateKey))
    {
        LogError("[%s] ED25519_sign() for |binded_id_pka_signature| failed: %s",
                 current_stage,
                 ERR_error_string(ERR_get_error(), NULL));
        KGC_SERVE_SEND_REGISTER_RESPONSE_FAILURE;
    }

    if (receive_buffer.data[KGC_MSG_TYPE_LENGTH] == KGC_ENTITY_TYPE_CLIENT)
    {
        uint8_t *belonging_server_count_ptr =
            receive_buffer.data + KGC_MSG_TYPE_LENGTH +
            KGC_ENTITY_TYPE_LENGTH +
            ENTITY_IDENTITY_LENGTH +
            CLTLS_ENTITY_PUBLIC_KEY_LENGTH;

        uint16_t belonging_server_count = ntohs(
            *((uint16_t *)(belonging_server_count_ptr)));

        uint8_t *belonging_server_identities =
            belonging_server_count_ptr + KGC_BELONGING_SERVER_COUNT_LENGTH;

        for (int i = 0; i < belonging_server_count; i++)
        {
            uint8_t *current_identity =
                belonging_server_identities +
                i * (ENTITY_IDENTITY_LENGTH + KGC_BELONGING_SERVER_PORT_LENGTH);

            uint16_t current_port =
                ntohs(*((uint16_t *)(current_identity + ENTITY_IDENTITY_LENGTH)));

            IdIp belonging_server_id_ip_key;
            memcpy(belonging_server_id_ip_key.id,
                   current_identity,
                   ENTITY_IDENTITY_LENGTH);
            set_IdIp_node *belonging_server_id_ip =
                set_IdIp_find(&kServerIdIpTable, belonging_server_id_ip_key);

            char current_identity_hex[ENTITY_IDENTITY_HEX_STR_LENGTH] = {0};
            Bin2Hex(current_identity,
                    current_identity_hex,
                    ENTITY_IDENTITY_LENGTH);

            if (belonging_server_id_ip == set_IdIp_end(&kServerIdIpTable))
            {
                LogError("[%s] Belonging server ID %s not in ID/IP table",
                         current_stage,
                         current_identity_hex);
                KGC_SERVE_SEND_REGISTER_RESPONSE_FAILURE;
            }

            int belonging_server_socket_fd = 0;
            if (!TcpConnectToServer(belonging_server_id_ip->key.ip,
                                    current_port,
                                    &belonging_server_socket_fd))
            {
                LogError("[%s] Cannot connect to belonging server %s",
                         current_stage,
                         current_identity_hex);
                KGC_SERVE_SEND_REGISTER_RESPONSE_FAILURE;
            }

            ClientHandshakeCtx client_handshake_ctx = {
                .socket_fd = belonging_server_socket_fd,
                .application_layer_protocol = CLTLS_PROTOCOL_KGC,
                .client_cipher_suite_set = &kServerCipherSuiteSet,
                .client_identity = kServerIdentity,
                .client_private_key = kServerPrivateKey,
                .client_public_key = kServerPublicKey,
                .kgc_public_key = kKgcPublicKey,
                .server_identity = belonging_server_id_ip->key.id};

            HandshakeResult client_handshake_result;

            if (!ClientHandshake(&client_handshake_ctx,
                                 &client_handshake_result))
            {
                LogError("[%s] CL-TLS handshake failed with belonging server %s",
                         current_stage,
                         current_identity_hex);
                KGC_SERVE_BS_CLOSE_SEND_FAILURE;
            }

            ByteVecResize(&send_buffer,
                          KGC_ADD_CLIENT_REQUEST_HEADER_LENGTH);
            send_buffer.data[0] = KGC_MSG_TYPE_ADD_CLIENT_REQUEST;
            memcpy(send_buffer.data + KGC_MSG_TYPE_LENGTH,
                   client_identity,
                   ENTITY_IDENTITY_LENGTH);

            if (!SendApplicationData(belonging_server_socket_fd,
                                     &client_handshake_result,
                                     true,
                                     &send_buffer))
            {
                LogError("[%s] Failed to send ADD_CLIENT_REQUEST to belonging server %s",
                         current_stage,
                         current_identity_hex);
                KGC_SERVE_BS_CLOSE_SEND_FAILURE;
            }

            if (!ReceiveApplicationData(belonging_server_socket_fd,
                                        &client_handshake_result,
                                        true,
                                        &receive_buffer))
            {
                LogError("[%s] Failed to receive ADD_CLIENT_RESPONSE from "
                         "belonging server %s",
                         current_stage,
                         current_identity_hex);
                KGC_SERVE_BS_CLOSE_SEND_FAILURE;
            }

            if (receive_buffer.data[0] != KGC_MSG_TYPE_ADD_CLIENT_RESPONSE)
            {
                LogError("[%s] Unexpected KGC message type received from "
                         "belonging server %s; ADD_CLIENT_RESPONSE expected",
                         current_stage,
                         current_identity_hex);
                KGC_SERVE_BS_SEND_ERROR_STOP_NOTIFY_CLOSE_SEND_FAILURE(
                    CLTLS_ERROR_APPLICATION_LAYER_ERROR);
            }

            if (receive_buffer.data[KGC_MSG_TYPE_LENGTH] ==
                KGC_ADD_CLIENT_STATUS_FAILURE)
            {
                LogError("[%s] Belonging server %s reports ADD_CLIENT_STATUS_FAILURE",
                         current_stage,
                         current_identity_hex);
                KGC_SERVE_BS_SEND_ERROR_STOP_NOTIFY_CLOSE_SEND_FAILURE(
                    CLTLS_ERROR_APPLICATION_LAYER_ERROR);
            }

            TcpClose(belonging_server_socket_fd);
        }
    }

    ByteVecResize(&send_buffer, KGC_REGISTER_RESPONSE_SUCCESS_HEADER_LENGTH);
    send_buffer.data[0] = KGC_MSG_TYPE_RESIGTER_RESPONSE;
    send_buffer.data[KGC_MSG_TYPE_LENGTH] = KGC_REGISTER_STATUS_SUCCESS;
    memcpy(send_buffer.data + KGC_MSG_TYPE_LENGTH + KGC_STATUS_CODE_LENGTH,
           binded_id_pka_signature,
           CLTLS_ENTITY_PKA_ID_SIGNATURE_LENGTH);

    if (!SendApplicationData(socket_fd,
                             handshake_result,
                             false,
                             &send_buffer))
    {
        KGC_SERVE_FREE_RETURN_FALSE;
    }

    ByteVecFree(&send_buffer);
    ByteVecFree(&receive_buffer);
    return true;
}

static bool ProxyServe(const ServerHandshakeCtx *ctx)
{
}

void *ServerTcpRequestHandler(void *arg)
{
    const TcpRequestHandlerCtx *ctx = (const TcpRequestHandlerCtx *)arg;
    const ServerArgs *server_args = (const ServerArgs *)ctx->extra;

    ServerHandshakeCtx server_handshake_ctx = {
        .kgc_public_key = kKgcPublicKey,
        .mode = server_args->mode,
        .preferred_cipher_suite = server_args->preferred_cipher_suite,
        .server_cipher_suite_set = &kServerCipherSuiteSet,
        .server_identity = kServerIdentity,
        .server_permitted_id_set = &kServerPermittedIdSet,
        .server_private_key = kServerPrivateKey,
        .server_public_key = kServerPublicKey,
        .socket_fd = ctx->client_socket_fd};

    HandshakeResult handshake_result;
    uint8_t application_layer_protocol = 0;
    if (!ServerHandshake(&server_handshake_ctx,
                         &handshake_result,
                         &application_layer_protocol))
    {
        TcpClose(ctx->client_socket_fd);
        free(arg);
        return NULL;
    }

    return NULL;
}
