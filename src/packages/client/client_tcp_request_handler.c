#include "client_tcp_request_handler.h"

void *ClientTcpRequestHandler(void *arg)
{
    LogInfo("MQTT proxy service started");

    const TcpRequestHandlerCtx *ctx = (const TcpRequestHandlerCtx *)arg;
    // const ClientArgs *client_args = (const ClientArgs *)ctx->extra;

    // Keep client connection until connected to server
    while (true)
    {
        ByteVec buffer;

        ByteVecInitWithCapacity(&buffer, INITIAL_SOCKET_BUFFER_CAPACITY);

        ByteVecResize(&buffer, CONNCTL_CONNECT_REQUEST_HEADER_LENGTH);

        if (!TcpRecv(ctx->client_socket_fd,
                     buffer.data,
                     CONNCTL_CONNECT_REQUEST_HEADER_LENGTH))
        {
            LogError("Failed to receive CONNCTL connect request");
            CLIENT_CLOSE_C_FREE_RETURN;
        }

        char server_id_hex[ENTITY_IDENTITY_HEX_STR_LENGTH] = {0};
        Bin2Hex(buffer.data + CONNCTL_MSG_TYPE_LENGTH,
                server_id_hex,
                ENTITY_IDENTITY_LENGTH);

        uint16_t server_port = ntohs(
            *((uint16_t *)(buffer.data +
                           CONNCTL_MSG_TYPE_LENGTH +
                           ENTITY_IDENTITY_LENGTH)));

        LogInfo("Received CONNCTL connection request to server %s on port %hu",
                server_id_hex,
                server_port);

        IdIp server_idip_key;
        memcpy(server_idip_key.id,
               buffer.data + CONNCTL_MSG_TYPE_LENGTH,
               ENTITY_IDENTITY_LENGTH);

        set_IdIp_node *server_idip = set_IdIp_find(&kClientIdIpTable, server_idip_key);
        if (server_idip == set_IdIp_end(&kClientIdIpTable))
        {
            LogError("Server ID %s not in ID/IP table",
                     server_id_hex);
            CLIENT_SEND_CONNECT_FAILURE_CONTINUE;
        }

        int server_socket_fd = 0;
        if (!TcpConnectToServer(server_idip->key.ip, server_port, &server_socket_fd))
        {
            LogError("Failed to connect to server %s",
                     server_id_hex);
            CLIENT_SEND_CONNECT_FAILURE_CONTINUE;
        }

        ClientHandshakeCtx client_handshake_ctx = {
            .socket_fd = server_socket_fd,
            .application_layer_protocol = CLTLS_PROTOCOL_MQTT,
            .client_cipher_suite_set = &kClientCipherSuiteSet,
            .client_identity = kClientIdentity,
            .client_private_key = kClientPrivateKey,
            .client_public_key = kClientPublicKey,
            .kgc_public_key = kKgcPublicKey,
            .server_identity = server_idip->key.id};

        HandshakeResult client_handshake_result;

        if (!ClientHandshake(&client_handshake_ctx,
                             &client_handshake_result))
        {
            LogError("CL-TLS handshake failed with server");
            CLIENT_SEND_CONNECT_FAILURE_CLOSE_S_CONTINUE;
        }

        ByteVecResize(&buffer, CONNCTL_CONNECT_RESPONSE_HEADER_LENGTH);

        if (!ReceiveApplicationData(server_socket_fd,
                                    &client_handshake_result,
                                    true,
                                    &buffer))
        {
            LogError("Failed to receive CONNCTL connect response from server");
            CLIENT_SEND_CONNECT_FAILURE_CLOSE_S_CONTINUE;
        }

        if (buffer.data[0] != CONNCTL_MSG_TYPE_CONNECT_RESPONSE)
        {
            LogError("Unexpected message type received from server; "
                     "CONNECT_RESPONSE expected");
            CLIENT_SEND_ERROR_STOP_NOTIFY_SEND_CONNECT_FAILURE_CLOSE_S_CONTINUE(
                CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
        }

        if (buffer.data[CONNCTL_MSG_TYPE_LENGTH] == CONNCTL_CONNECT_STATUS_FAILURE)
        {
            LogError("Server reports it failed to connect to proxy forward server");
            CLIENT_SEND_ERROR_STOP_NOTIFY_SEND_CONNECT_FAILURE_CLOSE_S_CONTINUE(
                CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
        }

        LogInfo("Server reports it successfully connected to proxy forward server");

        buffer.data[0] = CONNCTL_MSG_TYPE_CONNECT_RESPONSE;
        buffer.data[CONNCTL_MSG_TYPE_LENGTH] = CONNCTL_CONNECT_STATUS_SUCCESS;
        if (!TcpSend(ctx->client_socket_fd,
                     buffer.data,
                     CONNCTL_CONNECT_RESPONSE_HEADER_LENGTH))
        {
            LogError("Failed to send CONNCTL connect response");
            CLIENT_SEND_ERROR_STOP_NOTIFY_CLOSE_CS_FREE_RETURN(
                CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
        }

        // Loop until we receive MQTT DISCONNECT
        while (true)
        {
            clock_t start_time = clock();

            // Receive client MQTT fixed header
            ByteVecResize(&buffer, MQTT_FIXED_HEADER_LENGTH);

            if (!TcpRecv(ctx->client_socket_fd,
                         buffer.data,
                         MQTT_FIXED_HEADER_LENGTH))
            {
                LogError("Failed to receive MQTT fixed header from client");
                CLIENT_SEND_ERROR_STOP_NOTIFY_CLOSE_CS_FREE_RETURN(
                    CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
            }

            // Decode MQTT remaining length
            uint8_t current_byte = buffer.data[1];
            size_t mqtt_remaining_length = 0;
            size_t multiplier = 1;

            while (current_byte & 0x80U)
            {
                mqtt_remaining_length += multiplier * (current_byte & 0x7FU);
                multiplier *= 128;
                if (!TcpRecv(ctx->client_socket_fd,
                             &current_byte,
                             1))
                {
                    LogError("Failed to receive MQTT remaining length from client");
                    CLIENT_SEND_ERROR_STOP_NOTIFY_CLOSE_CS_FREE_RETURN(
                        CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
                }

                ByteVecPushBack(&buffer, current_byte);
            }

            mqtt_remaining_length += multiplier * (current_byte & 0x7FU);

            uint8_t mqtt_msg_type = MQTT_MSG_TYPE(buffer.data[0]);
            LogInfo("Received %s (0x%02hhX) with remaining length %zu from client",
                    GetMqttMessageType(mqtt_msg_type),
                    mqtt_msg_type,
                    mqtt_remaining_length);

            size_t remaining_read_size = mqtt_remaining_length;

            // Forward client data in blocks
            if (remaining_read_size == 0)
            {
                if (!SendApplicationData(server_socket_fd,
                                         &client_handshake_result,
                                         true,
                                         &buffer))
                {
                    LogError("Failed to forward MQTT packet to server");
                    CLIENT_CLOSE_CS_FREE_RETURN;
                }
            }
            else
            {
                size_t current_read_size = MIN(
                    remaining_read_size,
                    kSocketBlockSize - buffer.size);

                // Used in first block receive to append data after MQTT header.
                // Always be 0 when receiving further blocks.
                size_t receive_buffer_offset = buffer.size;

                ByteVecResizeBy(&buffer, current_read_size);

                while (remaining_read_size > 0)
                {
                    if (!TcpRecv(ctx->client_socket_fd,
                                 buffer.data + receive_buffer_offset,
                                 current_read_size))
                    {
                        LogError("Failed to receive MQTT packet from client");
                        CLIENT_SEND_ERROR_STOP_NOTIFY_CLOSE_CS_FREE_RETURN(
                            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
                    }

                    if (!SendApplicationData(server_socket_fd,
                                             &client_handshake_result,
                                             true,
                                             &buffer))
                    {
                        LogError("Failed to forward MQTT packet to server");
                        CLIENT_CLOSE_CS_FREE_RETURN;
                    }

                    remaining_read_size -= current_read_size;
                    current_read_size = MIN(remaining_read_size, kSocketBlockSize);
                    ByteVecResize(&buffer, current_read_size);

                    receive_buffer_offset = 0;
                }
            }

            LogInfo("Forwarded %s (0x%02hhX) to server",
                    GetMqttMessageType(mqtt_msg_type),
                    mqtt_msg_type);

            if (mqtt_msg_type == MQTT_MSG_TYPE_DISCONNECT)
            {
                break;
            }

            // Forward server data in blocks
            if (!ReceiveApplicationData(server_socket_fd,
                                        &client_handshake_result,
                                        true,
                                        &buffer))
            {
                LogError("Failed to receive MQTT packet from server");
                CLIENT_CLOSE_CS_FREE_RETURN;
            }

            mqtt_remaining_length = DecodeMqttRemainingLength(buffer.data + 1);

            mqtt_msg_type = MQTT_MSG_TYPE(buffer.data[0]);

            LogInfo("Received %s (0x%02hhX) with remaining length %zu from server",
                    GetMqttMessageType(mqtt_msg_type),
                    mqtt_msg_type,
                    mqtt_remaining_length);

            if (!TcpSend(ctx->client_socket_fd, buffer.data, buffer.size))
            {
                LogError("Failed to forward MQTT packet to client");
                CLIENT_SEND_ERROR_STOP_NOTIFY_CLOSE_CS_FREE_RETURN(
                    CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
            }

            remaining_read_size =
                mqtt_remaining_length +
                1 +
                GetMqttRemainingLengthByteCount(mqtt_remaining_length) -
                buffer.size;

            while (remaining_read_size > 0)
            {
                if (!ReceiveApplicationData(server_socket_fd,
                                            &client_handshake_result,
                                            true,
                                            &buffer))
                {
                    LogError("Failed to receive MQTT packet from server");
                    CLIENT_CLOSE_CS_FREE_RETURN;
                }

                if (!TcpSend(ctx->client_socket_fd, buffer.data, buffer.size))
                {
                    LogError("Failed to forward MQTT packet to client");
                    CLIENT_SEND_ERROR_STOP_NOTIFY_CLOSE_CS_FREE_RETURN(
                        CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
                }

                remaining_read_size -= buffer.size;
            }

            clock_t end_time = clock();

            LogInfo("Forwarded %s (0x%02hhX) to client",
                    GetMqttMessageType(mqtt_msg_type),
                    mqtt_msg_type);

            if (kPrintTiming)
            {
                LogTiming("Client proxy forwarding finished in %.03fms",
                          MS(end_time - start_time));
            }
        }

        TcpClose(server_socket_fd);

        ByteVecFree(&buffer);

        LogSuccess("MQTT proxy service successfully finished");
    }

    TcpClose(ctx->client_socket_fd);
    free(arg);
    return NULL;
}
