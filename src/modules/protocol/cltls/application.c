#include "application.h"

bool SendApplicationData(const int socket_fd,
                         HandshakeResult *handshake_result,
                         const bool is_client,
                         const ByteVec *data)
{
    ByteVec buffer;

    const char *current_stage = "SEND Application Data";

    ByteVecInitWithCapacity(&buffer, INITIAL_SOCKET_BUFFER_CAPACITY);

    ByteVecResize(&buffer,
                  CLTLS_COMMON_HEADER_LENGTH + data->size + MAX_ENC_EXTRA_SIZE);

    size_t encrypted_length = 0;

    if (!handshake_result->aead->Encrypt(
            data->data, data->size,
            CLTLS_REMAINING_HEADER(buffer.data), &encrypted_length,
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
        APPLICATION_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    ByteVecResize(&buffer, CLTLS_COMMON_HEADER_LENGTH + encrypted_length);

    CLTLS_SET_COMMON_HEADER(buffer.data,
                            CLTLS_MSG_TYPE_APPLICATION_DATA,
                            encrypted_length);

    if (!TcpSend(socket_fd,
                 buffer.data,
                 buffer.size))
    {
        LogError("[%s] Failed to send Application Data",
                 current_stage);
        APPLICATION_FREE_RETURN_FALSE;
    }

    ByteVecFree(&buffer);
    return true;
}

bool ReceiveApplicationData(const int socket_fd,
                            HandshakeResult *handshake_result,
                            const bool is_client,
                            ByteVec *data)
{
    ByteVec buffer;

    ByteVecInitWithCapacity(&buffer, INITIAL_SOCKET_BUFFER_CAPACITY);

    size_t receive_remaining_length = 0;

    const char *current_stage = "RECEIVE Application Data";

    ByteVecResize(&buffer, CLTLS_COMMON_HEADER_LENGTH);

    if (!TcpRecv(socket_fd,
                 buffer.data,
                 CLTLS_COMMON_HEADER_LENGTH))
    {
        LogError("[%s] Failed to receive common header of Application Data",
                 current_stage);
        ByteVecFree(&buffer);
        return false;
    }

    if (CLTLS_MSG_TYPE(buffer.data) != CLTLS_MSG_TYPE_APPLICATION_DATA &&
        CLTLS_MSG_TYPE(buffer.data) != CLTLS_MSG_TYPE_ERROR_STOP_NOTIFY)
    {
        LogError("[%s] Invalid message type received (0x%02hhX)",
                 current_stage,
                 CLTLS_MSG_TYPE(buffer.data));
        APPLICATION_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_UNEXPECTED_MSG_TYPE);
    }

    receive_remaining_length = CLTLS_REMAINING_LENGTH(buffer.data);

    ByteVecResizeBy(&buffer, receive_remaining_length);

    if (!TcpRecv(socket_fd,
                 CLTLS_REMAINING_HEADER(buffer.data),
                 receive_remaining_length))
    {
        LogError("[%s] Failed to receive message remaining part",
                 current_stage);

        APPLICATION_FREE_RETURN_FALSE;
    }

    if (CLTLS_MSG_TYPE(buffer.data) == CLTLS_MSG_TYPE_ERROR_STOP_NOTIFY)
    {
        LogError("[%s] The other party send ERROR_STOP_NOTIFY: %s",
                 current_stage,
                 GetCltlsErrorMessage(
                     CLTLS_REMAINING_HEADER(buffer.data[0])));

        APPLICATION_FREE_RETURN_FALSE;
    }

    ByteVecResize(data, receive_remaining_length);

    size_t decrypted_length = 0;

    if (!handshake_result->aead->Decrypt(
            CLTLS_REMAINING_HEADER(buffer.data),
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
        APPLICATION_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(
            CLTLS_ERROR_INTERNAL_EXECUTION_ERROR);
    }

    ByteVecResize(data, decrypted_length);

    ByteVecFree(&buffer);

    return true;
}