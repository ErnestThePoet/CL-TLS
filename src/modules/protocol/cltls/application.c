#include "application.h"

void SendCloseConnection(const int socket_fd)
{
    uint8_t send_data[CLTLS_CLOSE_CONNECTION_HEADER_LENGTH] = {0};
    CLTLS_SET_COMMON_HEADER(send_data,
                            CLTLS_MSG_TYPE_CLOSE_CONNECTION,
                            0);
    if (!TcpSend(socket_fd,
                 send_data,
                 CLTLS_CLOSE_CONNECTION_HEADER_LENGTH))
    {
        LogError("[SEND Close Connection] Failed to send Close Connection");
    }
}

bool SendApplicationData(const int socket_fd,
                         const HandshakeResult *handshake_result,
                         const bool is_client,
                         const ByteVec *data)
{
    ByteVec send_buffer;

    const char *current_stage = "SEND Application Data";

    ByteVecInitWithCapacity(&send_buffer, INITIAL_SOCKET_BUFFER_CAPACITY);

    ByteVecResize(&send_buffer,
                  CLTLS_COMMON_HEADER_LENGTH + data->size + MAX_ENC_EXTRA_SIZE);

    size_t encrypted_length = 0;

    if (!handshake_result->aead->Encrypt(
            data->data, data->size,
            CLTLS_REMAINING_HEADER(send_buffer.data), &encrypted_length,
            NULL, 0,
            is_client
                ? handshake_result->client_key
                : handshake_result->server_key,
            is_client
                ? handshake_result->client_npub_iv
                : handshake_result->server_npub_iv,
            &handshake_result->iv_length))
    {
        LogError("[%s] Encryption of Application Data failed",
                 current_stage);
        APPLICATION_SEND_SEND_ERROR_STOP_NOTIFY(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    ByteVecResize(&send_buffer, CLTLS_COMMON_HEADER_LENGTH + encrypted_length);

    CLTLS_SET_COMMON_HEADER(send_buffer.data,
                            CLTLS_MSG_TYPE_APPLICATION_DATA,
                            encrypted_length);

    if (!TcpSend(socket_fd,
                 send_buffer.data,
                 send_buffer.size))
    {
        LogError("[%s] Failed to send Application Data",
                 current_stage);
        APPLICATION_SEND_FREE_RETURN_FALSE;
    }

    ByteVecFree(&send_buffer);
    return true;
}

bool ReceiveApplicationData(const int socket_fd,
                            const HandshakeResult *handshake_result,
                            const bool is_client,
                            ByteVec *data,
                            bool *connection_closed_ret)
{
    ByteVec receive_buffer;

    ByteVecInitWithCapacity(&receive_buffer, INITIAL_SOCKET_BUFFER_CAPACITY);

    size_t receive_remaining_length = 0;

    const char *current_stage = "RECEIVE Application Data";

    ByteVecResize(&receive_buffer, CLTLS_COMMON_HEADER_LENGTH);

    if (!TcpRecv(socket_fd,
                 receive_buffer.data,
                 CLTLS_COMMON_HEADER_LENGTH))
    {
        LogError("[%s] Failed to receive common header of Application Data",
                 current_stage);
        ByteVecFree(&receive_buffer);
        return false;
    }

    if (CLTLS_MSG_TYPE(receive_buffer.data) != CLTLS_MSG_TYPE_APPLICATION_DATA &&
        CLTLS_MSG_TYPE(receive_buffer.data) != CLTLS_MSG_TYPE_CLOSE_CONNECTION &&
        CLTLS_MSG_TYPE(receive_buffer.data) != CLTLS_MSG_TYPE_ERROR_STOP_NOTIFY)
    {
        LogError("[%s] Invalid message type received",
                 current_stage);
        APPLICATION_RECEIVE_SEND_ERROR_STOP_NOTIFY(
            CLTLS_ERROR_UNEXPECTED_MSG_TYPE);
    }

    receive_remaining_length = CLTLS_REMAINING_LENGTH(receive_buffer.data);

    ByteVecResizeBy(&receive_buffer, receive_remaining_length);

    if (!TcpRecv(socket_fd,
                 CLTLS_REMAINING_HEADER(receive_buffer.data),
                 receive_remaining_length))
    {
        LogError("[%s] Failed to receive message remaining part",
                 current_stage);

        APPLICATION_RECEIVE_FREE_RETURN_FALSE;
    }

    switch (CLTLS_MSG_TYPE(receive_buffer.data))
    {
    case CLTLS_MSG_TYPE_CLOSE_CONNECTION:
        LogInfo("Connection gracefully closed");
        ByteVecFree(&receive_buffer);
        *connection_closed_ret = true;
        return true;
    case CLTLS_MSG_TYPE_ERROR_STOP_NOTIFY:
        LogError("[%s] The other party send ERROR_STOP_NOTIFY: %s",
                 current_stage,
                 GetCltlsErrorMessage(
                     CLTLS_REMAINING_HEADER(receive_buffer.data[0])));

        APPLICATION_RECEIVE_FREE_RETURN_FALSE;
    default:
        break;
    }

    ByteVecResize(data, receive_remaining_length);

    size_t decrypted_length = 0;

    if (!handshake_result->aead->Decrypt(
            CLTLS_REMAINING_HEADER(receive_buffer.data),
            receive_remaining_length,
            data->data, &decrypted_length,
            NULL, 0,
            is_client
                ? handshake_result->server_key
                : handshake_result->client_key,
            is_client
                ? handshake_result->server_npub_iv
                : handshake_result->client_npub_iv,
            &handshake_result->iv_length))
    {
        LogError("[%s] Decryption of Application Data failed",
                 current_stage);
        APPLICATION_RECEIVE_SEND_ERROR_STOP_NOTIFY(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    ByteVecResize(data, decrypted_length);

    ByteVecFree(&receive_buffer);

    *connection_closed_ret = false;
    return true;
}