#include "server_tcp_request_handler.h"

static bool KgcServe(const int socket_fd,
                     HandshakeResult *handshake_result)
{
    ByteVec send_buffer;
    ByteVec receive_buffer;

    ByteVecInitWithCapacity(&send_buffer, INITIAL_SOCKET_BUFFER_CAPACITY);
    ByteVecInitWithCapacity(&receive_buffer, INITIAL_SOCKET_BUFFER_CAPACITY);

    if (!ReceiveApplicationData(socket_fd,
                                handshake_result,
                                false,
                                &receive_buffer))
    {
        KGC_SERVE_FREE_RETURN_FALSE;
    }

    if (receive_buffer.data[0] != KGC_MSG_TYPE_REGISTER_REQUEST)
    {
        LogError("Unexpected KGC message type; "
                 "KGC_MSG_TYPE_REGISTER_REQUEST expected");
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
        LogError("ED25519_sign() for |binded_id_pka_signature| failed: %s",
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
                LogError("Belonging server ID %s not in ID/IP table",
                         current_identity_hex);
                KGC_SERVE_SEND_REGISTER_RESPONSE_FAILURE;
            }

            int belonging_server_socket_fd = 0;
            if (!TcpConnectToServer(belonging_server_id_ip->key.ip,
                                    current_port,
                                    &belonging_server_socket_fd))
            {
                LogError("Cannot connect to belonging server %s",
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
                LogError("CL-TLS handshake failed with belonging server %s",
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
                LogError("Failed to send ADD_CLIENT_REQUEST to belonging server %s",
                         current_identity_hex);
                KGC_SERVE_BS_CLOSE_SEND_FAILURE;
            }

            if (!ReceiveApplicationData(belonging_server_socket_fd,
                                        &client_handshake_result,
                                        true,
                                        &receive_buffer))
            {
                LogError("Failed to receive ADD_CLIENT_RESPONSE from "
                         "belonging server %s",
                         current_identity_hex);
                KGC_SERVE_BS_CLOSE_SEND_FAILURE;
            }

            TcpClose(belonging_server_socket_fd);

            if (receive_buffer.data[0] != KGC_MSG_TYPE_ADD_CLIENT_RESPONSE)
            {
                LogError("Unexpected KGC message type received from "
                         "belonging server %s; ADD_CLIENT_RESPONSE expected",
                         current_identity_hex);
                KGC_SERVE_SEND_REGISTER_RESPONSE_FAILURE;
            }

            if (receive_buffer.data[KGC_MSG_TYPE_LENGTH] ==
                KGC_ADD_CLIENT_STATUS_FAILURE)
            {
                LogError("Belonging server %s reports ADD_CLIENT_STATUS_FAILURE",
                         current_identity_hex);
                KGC_SERVE_SEND_REGISTER_RESPONSE_FAILURE;
            }
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

static bool MqttProxyServe(const int socket_fd,
                           HandshakeResult *handshake_result,
                           const char *forward_ip,
                           const uint16_t forward_port)
{
    ByteVec buffer;

    ByteVecInitWithCapacity(&buffer, INITIAL_SOCKET_BUFFER_CAPACITY);

    int forward_socket_fd = 0;
    if (!TcpConnectToServer(forward_ip, forward_port, &forward_socket_fd))
    {
        LogError("Failed to connect to proxy forward server");
        MQTT_PROXY_SERVE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    // Loop until we receive MQTT DISCONNECT
    while (true)
    {
        // Forward client data in blocks
        if (!ReceiveApplicationData(socket_fd,
                                    handshake_result,
                                    false,
                                    &buffer))
        {
            LogError("Failed to receive MQTT packet from client");
            MQTT_PROXY_SERVE_CLOSE_FREE_RETURN_FALSE;
        }

        uint8_t mqtt_msg_type = MQTT_MSG_TYPE(buffer.data[0]);
        LogInfo("Received %s from client", GetMqttMessageType(mqtt_msg_type));

        if (!TcpSend(forward_socket_fd,
                     buffer.data,
                     buffer.size))
        {
            LogError("Failed to forward MQTT packet to server");
            MQTT_PROXY_SERVE_SEND_ERROR_STOP_NOTIFY_CLOSE_FREE_RETURN_FALSE(
                CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
        }

        size_t current_byte_index = 1;
        uint8_t current_byte = buffer.data[current_byte_index];
        size_t mqtt_remaining_length = 0;
        size_t multiplier = 1;

        while (current_byte & 0x80U)
        {
            mqtt_remaining_length += multiplier * (current_byte & 0x7FU);
            multiplier *= 128;
            current_byte = buffer.data[++current_byte_index];
        }

        mqtt_remaining_length += multiplier * (current_byte & 0x7FU);

        size_t remaining_read_size = mqtt_remaining_length - buffer.size;

        while (remaining_read_size > 0)
        {
            if (!ReceiveApplicationData(socket_fd,
                                        handshake_result,
                                        false,
                                        &buffer))
            {
                LogError("Failed to receive MQTT packet from client");
                MQTT_PROXY_SERVE_CLOSE_FREE_RETURN_FALSE;
            }

            if (!TcpSend(forward_socket_fd,
                         buffer.data,
                         buffer.size))
            {
                LogError("Failed to forward MQTT packet to server");
                MQTT_PROXY_SERVE_SEND_ERROR_STOP_NOTIFY_CLOSE_FREE_RETURN_FALSE(
                    CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
            }

            remaining_read_size -= buffer.size;
        }

        if (mqtt_msg_type == MQTT_MSG_TYPE_DISCONNECT)
        {
            break;
        }

        // Forward server data in blocks
        ByteVecResize(&buffer, MQTT_FIXED_HEADER_LENGTH);

        if (!TcpRecv(forward_socket_fd,
                     buffer.data,
                     MQTT_FIXED_HEADER_LENGTH))
        {
            LogError("Failed to receive MQTT fixed header from server");
            MQTT_PROXY_SERVE_SEND_ERROR_STOP_NOTIFY_CLOSE_FREE_RETURN_FALSE(
                CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
        }

        LogInfo("Received %s from server",
                GetMqttMessageType(MQTT_MSG_TYPE(buffer.data[0])));

        // Decode MQTT remaining length
        current_byte = buffer.data[1];
        mqtt_remaining_length = 0;
        multiplier = 1;

        while (current_byte & 0x80U)
        {
            mqtt_remaining_length += multiplier * (current_byte & 0x7FU);
            multiplier *= 128;
            if (!TcpRecv(socket_fd,
                         &current_byte,
                         1))
            {
                LogError("Failed to receive MQTT remaining length from server");
                MQTT_PROXY_SERVE_SEND_ERROR_STOP_NOTIFY_CLOSE_FREE_RETURN_FALSE(
                    CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
            }

            ByteVecPushBack(&buffer, current_byte);
        }

        mqtt_remaining_length += multiplier * (current_byte & 0x7FU);

        remaining_read_size = mqtt_remaining_length;

        // Forward client data in blocks
        size_t current_read_size = MIN(
            remaining_read_size,
            kSocketBlockSize - buffer.size);

        // Used in first block receive to append data after MQTT header.
        // Always be 0 when receiving further blocks.
        size_t receive_buffer_offset = buffer.size;

        ByteVecResizeBy(&buffer, current_read_size);

        while (remaining_read_size > 0)
        {
            if (!TcpRecv(forward_socket_fd,
                         buffer.data + receive_buffer_offset,
                         current_read_size))
            {
                LogError("Failed to receive MQTT packet from server");
                MQTT_PROXY_SERVE_SEND_ERROR_STOP_NOTIFY_CLOSE_FREE_RETURN_FALSE(
                    CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
            }

            if (!SendApplicationData(socket_fd,
                                     handshake_result,
                                     false,
                                     &buffer))
            {
                LogError("Failed to forward MQTT packet to client");
                MQTT_PROXY_SERVE_CLOSE_FREE_RETURN_FALSE;
            }

            remaining_read_size -= current_read_size;
            current_read_size = MIN(remaining_read_size, kSocketBlockSize);
            ByteVecResize(&buffer, current_read_size);

            receive_buffer_offset = 0;
        }
    }

    ByteVecFree(&buffer);
    return true;
}

static bool AddClientServe(const int socket_fd,
                           HandshakeResult *handshake_result)
{
    ByteVec send_buffer;
    ByteVec receive_buffer;

    ByteVecInitWithCapacity(&send_buffer, INITIAL_SOCKET_BUFFER_CAPACITY);
    ByteVecInitWithCapacity(&receive_buffer, INITIAL_SOCKET_BUFFER_CAPACITY);

    if (!ReceiveApplicationData(socket_fd,
                                handshake_result,
                                false,
                                &receive_buffer))
    {
        ADD_CLIENT_SERVE_FREE_RETURN_FALSE;
    }

    if (receive_buffer.data[0] != KGC_MSG_TYPE_ADD_CLIENT_REQUEST)
    {
        LogError("Unexpected KGC message type; "
                 "KGC_MSG_TYPE_ADD_CLIENT_REQUEST expected");
        ADD_CLIENT_SERVE_SEND_RESPONSE_FAILURE;
    }

    char new_id_hex[ENTITY_IDENTITY_HEX_STR_LENGTH] = {0};
    Bin2Hex(receive_buffer.data + KGC_MSG_TYPE_LENGTH,
            new_id_hex,
            ENTITY_IDENTITY_LENGTH);

    pthread_mutex_lock(&kServerPermittedIdsMutex);

    FILE *permitted_ids_fp = fopen(kServerPermittedIdsDatabasePath, "a");
    if (permitted_ids_fp == NULL)
    {
        LogError("Failed to open permitted IDs database file %s",
                 kServerPermittedIdsDatabasePath);
        pthread_mutex_unlock(&kServerPermittedIdsMutex);
        ADD_CLIENT_SERVE_SEND_RESPONSE_FAILURE;
    }

    if (fprintf(permitted_ids_fp, "%s\n", new_id_hex) != 1)
    {
        LogError("Failed to append new entry into permitted IDs database file %s",
                 kServerPermittedIdsDatabasePath);
        fclose(permitted_ids_fp);
        pthread_mutex_unlock(&kServerPermittedIdsMutex);
        ADD_CLIENT_SERVE_SEND_RESPONSE_FAILURE;
    }

    fclose(permitted_ids_fp);

    Id new_id;
    memcpy(new_id.id,
           receive_buffer.data + KGC_MSG_TYPE_LENGTH,
           ENTITY_IDENTITY_LENGTH);
    set_Id_insert(&kServerPermittedIdSet, new_id);

    pthread_mutex_unlock(&kServerPermittedIdsMutex);

    ByteVecResize(&send_buffer,
                  KGC_ADD_CLIENT_RESPONSE_HEADER_LENGTH);
    send_buffer.data[0] = KGC_MSG_TYPE_ADD_CLIENT_RESPONSE;
    send_buffer.data[1] = KGC_ADD_CLIENT_STATUS_SUCCESS;
    SendApplicationData(socket_fd,
                        handshake_result,
                        false,
                        &send_buffer);

    ByteVecFree(&send_buffer);
    ByteVecFree(&receive_buffer);
    return true;
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
        SERVER_CLOSE_FREE_RETURN;
    }

    switch (server_args->mode)
    {
    case SERVER_MODE_KGC:
        if (!KgcServe(ctx->client_socket_fd, &handshake_result))
        {
            SERVER_CLOSE_FREE_RETURN;
        }
        break;
    case SERVER_MODE_PROXY:
        switch (application_layer_protocol)
        {
        case CLTLS_PROTOCOL_MQTT:
            if (!MqttProxyServe(ctx->client_socket_fd,
                                &handshake_result,
                                server_args->forward_ip,
                                server_args->forward_port))
            {
                SERVER_CLOSE_FREE_RETURN;
            }
            break;
        case CLTLS_PROTOCOL_KGC:
            if (!AddClientServe(ctx->client_socket_fd, &handshake_result))
            {
                SERVER_CLOSE_FREE_RETURN;
            }
            break;
        }
        break;
    }

    SERVER_CLOSE_FREE_RETURN;
}
