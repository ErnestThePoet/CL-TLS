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

#define APPLICATION_SEND_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(ERROR_CODE) \
    do                                                                        \
    {                                                                         \
        CLTLS_SEND_ERROR_STOP_NOTIFY(socket_fd, ERROR_CODE);                  \
        APPLICATION_SEND_FREE_RETURN_FALSE;                                   \
    } while (false)

#define APPLICATION_RECEIVE_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(ERROR_CODE) \
    do                                                                           \
    {                                                                            \
        CLTLS_SEND_ERROR_STOP_NOTIFY(socket_fd, ERROR_CODE);                     \
        APPLICATION_RECEIVE_FREE_RETURN_FALSE;                                   \
    } while (false)

bool SendApplicationData(const int socket_fd,
                         const HandshakeResult *handshake_result,
                         const bool is_client,
                         const ByteVec *data);

bool ReceiveApplicationData(const int socket_fd,
                            const HandshakeResult *handshake_result,
                            const bool is_client,
                            ByteVec *data);

#endif