#ifndef APPLICATION_H_
#define APPLICATION_H_

#include "handshake.h"

#define APPLICATION_SEND_FREE_RETURN_FALSE \
    do                                     \
    {                                      \
        ByteVecFree(&send_buffer);         \
        return false;                      \
    } while (false)

#define APPLICATION_RECEIVE_FREE_RETURN_FALSE \
    do                                        \
    {                                         \
        ByteVecFree(&receive_buffer);         \
        return false;                         \
    } while (false)

#define APPLICATION_COMMON_SEND_ERROR_STOP_NOTIFY(ERROR_CODE)     \
    do                                                            \
    {                                                             \
        uint8_t error_stop_notify_send_data                       \
            [CLTLS_ERROR_STOP_NOTIFY_HEADER_LENGTH] = {0};        \
        CLTLS_SET_COMMON_HEADER(error_stop_notify_send_data,      \
                                CLTLS_MSG_TYPE_ERROR_STOP_NOTIFY, \
                                2);                               \
        error_stop_notify_send_data[3] = ERROR_CODE;              \
        TcpSend(socket_fd,                                        \
                error_stop_notify_send_data,                      \
                CLTLS_ERROR_STOP_NOTIFY_HEADER_LENGTH);           \
    } while (false)

#define APPLICATION_SEND_SEND_ERROR_STOP_NOTIFY(ERROR_CODE)    \
    do                                                         \
    {                                                          \
        APPLICATION_COMMON_SEND_ERROR_STOP_NOTIFY(ERROR_CODE); \
        APPLICATION_SEND_FREE_RETURN_FALSE;                    \
    } while (false)

#define APPLICATION_RECEIVE_SEND_ERROR_STOP_NOTIFY(ERROR_CODE) \
    do                                                         \
    {                                                          \
        APPLICATION_COMMON_SEND_ERROR_STOP_NOTIFY(ERROR_CODE); \
        APPLICATION_RECEIVE_FREE_RETURN_FALSE;                 \
    } while (false)

void SendCloseConnection(const int socket_fd);

bool SendApplicationData(const int socket_fd,
                         const HandshakeResult *handshake_result,
                         const bool is_client,
                         const ByteVec *data);

bool ReceiveApplicationData(const int socket_fd,
                            const HandshakeResult *handshake_result,
                            const bool is_client,
                            ByteVec *data,
                            bool *connection_closed_ret);

#endif