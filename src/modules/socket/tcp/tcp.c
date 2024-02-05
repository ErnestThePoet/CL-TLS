#include "tcp.h"

bool TcpSend(const int socket_fd, const char *buffer, const size_t send_size)
{
    const ssize_t sent_size = send(socket_fd, buffer, send_size, 0);
    if (sent_size < 0)
    {
        fprintf(stderr, "send() error: %s\n", STR_ERRNO);
        return false;
    }

    return sent_size == send_size;
}

bool TcpRecv(const int socket_fd, char *buffer, const size_t recv_size)
{
    size_t received_size = 0;

    while (received_size < recv_size)
    {
        const size_t remaining_receive_size = recv_size - received_size;
        const ssize_t current_receive_size = recv(
            socket_fd, buffer + received_size, remaining_receive_size, 0);
        if (current_receive_size < 0)
        {
            fprintf(stderr, "recv() error: %s\n", STR_ERRNO);
            return false;
        }

        received_size += current_receive_size;
    }

    return true;
}

bool TcpConnectToServer(
    const char *ip4_address, const uint16_t port, int *socket_fd_ret)
{
    const int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1)
    {
        fprintf(stderr, "socket() error: %s\n", STR_ERRNO);
        return false;
    }

    struct sockaddr_in server_sockaddr;
    const in_addr_t server_addr = inet_addr(ip4_address);
    if (server_addr == (in_addr_t)-1)
    {
        close(socket_fd);
        fprintf(stderr, "inet_addr() error: %s\n", STR_ERRNO);
        return false;
    }

    server_sockaddr.sin_addr.s_addr = server_addr;
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_port = htons(port);

    if (connect(socket_fd,
                (struct sockaddr *)&server_sockaddr,
                sizeof(struct sockaddr_in)) == -1)
    {
        close(socket_fd);
        fprintf(stderr, "connect() error: %s\n", STR_ERRNO);
        return false;
    }

    *socket_fd_ret = socket_fd;

    return true;
}

void TcpClose(const int socket_fd)
{
    close(socket_fd);
}

bool TcpCreateServer(uint16_t port, int *socket_fd_ret)
{
    const int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0)
    {
        fprintf(stderr, "socket() error: %s\n", STR_ERRNO);
        return false;
    }

    struct sockaddr_in server_sockaddr;
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_addr.s_addr = INADDR_ANY;
    server_sockaddr.sin_port = htons(port);

    if (bind(socket_fd,
             (struct sockaddr *)&server_sockaddr,
             sizeof(struct sockaddr_in)) < 0)
    {
        close(socket_fd);
        fprintf(stderr, "bind() error: %s\n", STR_ERRNO);
        return false;
    }

    if (listen(socket_fd, SOMAXCONN) < 0)
    {
        close(socket_fd);
        fprintf(stderr, "listen() error: %s\n", STR_ERRNO);
        return false;
    }

    *socket_fd_ret = socket_fd;

    return true;
}

void TcpRunServer(const int socket_fd, void *(*TcpHandleRequest)(void *))
{
    struct sockaddr_in client_sockaddr;
    socklen_t sockaddr_size = sizeof(struct sockaddr_in);

    while (true)
    {
        int client_socket = accept(
            socket_fd, (struct sockaddr *)&client_sockaddr, &sockaddr_size);
        if (client_socket == -1)
        {
            close(client_socket);
            fprintf(stderr, "accept() error: %s\n", STR_ERRNO);
            continue;
        }

        pthread_t client_thread;
        if (pthread_create(&client_thread, NULL, TcpHandleRequest, &client_socket))
        {
            close(client_socket);
            fprintf(stderr, "pthread_create() error: %s\n", STR_ERRNO);
            continue;
        }

        pthread_detach(client_thread);
    }

    close(socket_fd);
}