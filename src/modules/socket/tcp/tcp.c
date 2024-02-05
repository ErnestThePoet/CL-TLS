#include "tcp.h"

bool TcpSend(const int client_socket_fd,
             const char *buffer,
             const size_t send_size)
{
    const ssize_t sent_size = send(client_socket_fd, buffer, send_size, 0);
    if (sent_size < 0)
    {
        fprintf(stderr, "send() error: %s\n", STR_ERRNO);
        return false;
    }

    return sent_size == send_size;
}

bool TcpRecv(const int server_socket_fd,
             char *buffer,
             const size_t recv_size)
{
    size_t received_size = 0;

    while (received_size < recv_size)
    {
        const size_t remaining_receive_size = recv_size - received_size;
        const ssize_t current_receive_size = recv(
            server_socket_fd, buffer + received_size, remaining_receive_size, 0);
        if (current_receive_size < 0)
        {
            fprintf(stderr, "recv() error: %s\n", STR_ERRNO);
            return false;
        }

        received_size += current_receive_size;
    }

    return true;
}

bool TcpConnectToServer(const char *ip4_address,
                        const uint16_t port,
                        int *server_socket_fd_ret)
{
    const int server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket_fd == -1)
    {
        fprintf(stderr, "socket() error: %s\n", STR_ERRNO);
        return false;
    }

    struct sockaddr_in server_sockaddr;
    const in_addr_t server_addr = inet_addr(ip4_address);
    if (server_addr == (in_addr_t)-1)
    {
        close(server_socket_fd);
        fprintf(stderr, "inet_addr() error: %s\n", STR_ERRNO);
        return false;
    }

    server_sockaddr.sin_addr.s_addr = server_addr;
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_port = htons(port);

    if (connect(server_socket_fd,
                (struct sockaddr *)&server_sockaddr,
                sizeof(struct sockaddr_in)) == -1)
    {
        close(server_socket_fd);
        fprintf(stderr, "connect() error: %s\n", STR_ERRNO);
        return false;
    }

    *server_socket_fd_ret = server_socket_fd;

    return true;
}

void TcpClose(const int socket_fd)
{
    close(socket_fd);
}

bool TcpCreateServer(uint16_t port,
                     int *server_socket_fd_ret)
{
    const int server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket_fd < 0)
    {
        fprintf(stderr, "socket() error: %s\n", STR_ERRNO);
        return false;
    }

    struct sockaddr_in server_sockaddr;
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_addr.s_addr = INADDR_ANY;
    server_sockaddr.sin_port = htons(port);

    if (bind(server_socket_fd,
             (struct sockaddr *)&server_sockaddr,
             sizeof(struct sockaddr_in)) < 0)
    {
        close(server_socket_fd);
        fprintf(stderr, "bind() error: %s\n", STR_ERRNO);
        return false;
    }

    if (listen(server_socket_fd, SOMAXCONN) < 0)
    {
        close(server_socket_fd);
        fprintf(stderr, "listen() error: %s\n", STR_ERRNO);
        return false;
    }

    *server_socket_fd_ret = server_socket_fd;

    return true;
}

void TcpRunServer(const int server_socket_fd,
                  void *(*TcpHandleRequest)(void *),
                  void *ctx_extra)
{
    struct sockaddr_in client_sockaddr;
    socklen_t sockaddr_size = sizeof(struct sockaddr_in);

    while (true)
    {
        int client_socket_fd = accept(
            server_socket_fd, (struct sockaddr *)&client_sockaddr, &sockaddr_size);
        if (client_socket_fd == -1)
        {
            close(client_socket_fd);
            fprintf(stderr, "accept() error: %s\n", STR_ERRNO);
            continue;
        }

        TcpServerHandlerCtx *ctx = malloc(sizeof(TcpServerHandlerCtx));
        if (ctx == NULL)
        {
            close(client_socket_fd);
            fprintf(stderr, "Memory allocation for TcpServerHandlerCtx failed\n");
            exit(FAILURE);
        }

        ctx->client_socket_fd = client_socket_fd;
        ctx->extra = ctx_extra;

        pthread_t client_thread;
        if (pthread_create(&client_thread, NULL, TcpHandleRequest, ctx))
        {
            close(client_socket_fd);
            fprintf(stderr, "pthread_create() error: %s\n", STR_ERRNO);
            continue;
        }

        pthread_detach(client_thread);
    }

    close(server_socket_fd);
}