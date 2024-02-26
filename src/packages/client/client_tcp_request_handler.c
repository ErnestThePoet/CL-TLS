#include "client_tcp_request_handler.h"

void *ClientTcpRequestHandler(void *arg)
{
    const TcpRequestHandlerCtx *ctx = (const TcpRequestHandlerCtx *)arg;
    const ClientArgs *client_args = (const ClientArgs *)ctx->extra;

    ByteVec buffer;

    ByteVecInitWithCapacity(&buffer, INITIAL_SOCKET_BUFFER_CAPACITY);

    const char *current_stage = "RECEIVE Connect Request";

    ByteVecResize(&buffer, CONNCTL_CONNECT_REQUEST_HEADER_LENGTH);

    if (!TcpRecv(ctx->client_socket_fd,
                 buffer.data,
                 CONNCTL_CONNECT_REQUEST_HEADER_LENGTH))
    {
        LogError("[%s] Failed to receive CONNCTL Connect Request", current_stage);
        CLIENT_CLOSE_C_FREE_RETURN;
    }

    char server_id_hex[ENTITY_IDENTITY_HEX_STR_LENGTH] = {0};
    Bin2Hex(buffer.data + CONNCTL_MSG_TYPE_LENGTH,
            server_id_hex,
            ENTITY_IDENTITY_LENGTH);

    IdIp server_idip_key;
    memcpy(server_idip_key.id,
           buffer.data + CONNCTL_MSG_TYPE_LENGTH,
           ENTITY_IDENTITY_LENGTH);

    set_IdIp_node *server_idip = set_IdIp_find(&kClientIdIpTable, server_idip_key);
    if (server_idip == set_IdIp_end(&kClientIdIpTable))
    {
        LogError("[%s] Server ID %s not in ID/IP table",
                 current_stage,
                 server_id_hex);
        CLIENT_SEND_CONNECT_FAILURE_CLOSE_C_FREE_RETURN;
    }

    uint16_t server_port = ntohs(
        *((uint16_t *)(buffer.data +
                       CONNCTL_MSG_TYPE_LENGTH +
                       ENTITY_IDENTITY_LENGTH)));

    int server_socket_fd = 0;
    if (!TcpConnectToServer(server_idip->key.ip, server_port, &server_socket_fd))
    {
        LogError("[%s] Failed to connect to server %s",
                 current_stage,
                 server_id_hex);
        CLIENT_SEND_CONNECT_FAILURE_CLOSE_C_FREE_RETURN;
    }

    ClientHandshakeCtx client_handshake_ctx = {
        .socket_fd = server_socket_fd,
        .application_layer_protocol = CLTLS_PROTOCOL_KGC_REGISTER_REQUEST,
        .client_cipher_suite_set = &kClientCipherSuiteSet,
        .client_identity = kClientIdentity,
        .client_private_key = kClientPrivateKey,
        .client_public_key = kClientPublicKey,
        .kgc_public_key = kKgcPublicKey,
        .client_identity = kKgcIdentity};

    HandshakeResult client_handshake_result;

    if (!ClientHandshake(&client_handshake_ctx,
                         &client_handshake_result))
    {
        LogError("[%s] CL-TLS handshake failed with server %s",
                 current_stage,
                 server_id_hex);
        CLIENT_SEND_CONNECT_FAILURE_CLOSE_CS_FREE_RETURN;
    }

    ByteVecResize(&buffer, CONNCTL_CONNECT_RESPONSE_LENGTH);
    buffer.data[0] = CONNCTL_MSG_TYPE_CONNECT_RESPONSE;
    buffer.data[1] = CONNCTL_CONNECT_STATUS_SUCCESS;
    if (!TcpSend(ctx->client_socket_fd,
                 buffer.data,
                 CONNCTL_CONNECT_RESPONSE_LENGTH))
    {
        LogError("[%s] Failed to send CONNCTL Connect Response",
                 current_stage);
        CLIENT_SEND_ERROR_STOP_NOTIFY_CLOSE_CS_FREE_RETURN(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    // Loop until we receive MQTT DISCONNECT
    while (true)
    {
        // Receive client MQTT fixed header
        ByteVecResize(&buffer, MQTT_FIXED_HEADER_LENGTH);

        if (!TcpRecv(ctx->client_socket_fd,
                     buffer.data,
                     MQTT_FIXED_HEADER_LENGTH))
        {
            LogError("[%s] Failed to receive MQTT fixed header",
                     current_stage);
            CLIENT_SEND_ERROR_STOP_NOTIFY_CLOSE_CS_FREE_RETURN(
                CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
        }

        uint8_t mqtt_msg_type = (buffer.data[0] >> 4);
        LogInfo("Received %s", GetMqttMessageType(mqtt_msg_type));

        if (mqtt_msg_type == MQTT_MSG_TYPE_DISCONNECT)
        {
            break;
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
                LogError("[%s] Failed to receive MQTT remaining length",
                         current_stage);
                CLIENT_SEND_ERROR_STOP_NOTIFY_CLOSE_CS_FREE_RETURN(
                    CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
            }

            ByteVecPushBack(&buffer, current_byte);
        }

        mqtt_remaining_length += multiplier * (current_byte & 0x7FU);

        size_t remaining_read_size = mqtt_remaining_length;

        // Forward data in blocks
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
                LogError("[%s] Failed to receive MQTT payload from client",
                         current_stage);
                CLIENT_SEND_ERROR_STOP_NOTIFY_CLOSE_CS_FREE_RETURN(
                    CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
            }

            if (!SendApplicationData(server_socket_fd,
                                     &client_handshake_result,
                                     true,
                                     &buffer))
            {
                LogError("[%s] Failed to forward data to server",
                         current_stage);
                CLIENT_CLOSE_CS_FREE_RETURN;
            }

            remaining_read_size -= current_read_size;
            current_read_size = MIN(remaining_read_size, kSocketBlockSize);
            ByteVecResize(&buffer, current_read_size);

            receive_buffer_offset = 0;
        }

        // Send data back
        if (!ReceiveApplicationData(server_socket_fd,
                                    &client_handshake_result,
                                    true,
                                    &buffer))
        {
            LogError("[%s] Failed to receive data from server",
                     current_stage);
            CLIENT_CLOSE_CS_FREE_RETURN;
        }

        if (!TcpSend(ctx->client_socket_fd, buffer.data, buffer.size))
        {
            LogError("[%s] Failed to forward data to client",
                     current_stage);
            CLIENT_SEND_ERROR_STOP_NOTIFY_CLOSE_CS_FREE_RETURN(
                CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
        }
    }

    CLIENT_CLOSE_CS_FREE_RETURN;
}
