#include "tcp.h"

bool TcpSend(const int fd, const char *buffer, const size_t send_size)
{
    const ssize_t sent_size = send(fd, buffer, send_size, 0);
    if (sent_size < 0)
    {
        fprintf(stderr, "send() error: %s\n", STR_ERRNO);
        return false;
    }

    return sent_size == send_size;
}

bool TcpRecv(const int fd, char *buffer, const size_t recv_size)
{
    size_t received_size = 0;

    while (received_size < recv_size)
    {
        const size_t remaining_receive_size = recv_size - received_size;
        const ssize_t current_receive_size = recv(
            fd, buffer + received_size, remaining_receive_size, 0);
        if (current_receive_size < 0)
        {
            fprintf(stderr, "recv() error: %s\n", STR_ERRNO);
            return false;
        }

        received_size += current_receive_size;
    }

    return true;
}