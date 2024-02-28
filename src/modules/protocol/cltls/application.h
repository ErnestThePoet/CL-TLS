#ifndef APPLICATION_H_
#define APPLICATION_H_

#include "handshake.h"

#define APPLICATION_FREE_RETURN_FALSE \
    do                                \
    {                                 \
        ByteVecFree(&buffer);         \
        return false;                 \
    } while (false)

#define APPLICATION_SEND_ERROR_STOP_NOTIFY_FREE_RETURN_FALSE(ERROR_CODE) \
    do                                                                   \
    {                                                                    \
        CLTLS_SEND_ERROR_STOP_NOTIFY(socket_fd, ERROR_CODE);             \
        APPLICATION_FREE_RETURN_FALSE;                                   \
    } while (false)

bool SendApplicationData(const int socket_fd,
                         HandshakeResult *handshake_result,
                         const bool is_client,
                         const ByteVec *data);

bool ReceiveApplicationData(const int socket_fd,
                            HandshakeResult *handshake_result,
                            const bool is_client,
                            ByteVec *data);

#endif