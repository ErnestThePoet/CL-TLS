#include "tcp.h"

bool TcpSend(const int client_socket_fd,
             const uint8_t *buffer,
             const size_t send_size)
{
    size_t sent_size = 0;

    while (sent_size < send_size)
    {
        const size_t remaining_send_size = send_size - sent_size;
        const ssize_t current_send_size = send(
            client_socket_fd, buffer + sent_size, remaining_send_size, 0);
        // Unlike recv(), we will keep trying to send if it returns 0
        if (current_send_size < 0)
        {
            LogError("send() error: %s", STR_ERRNO);
            return false;
        }

        sent_size += current_send_size;
    }

    return true;
}

bool TcpRecv(const int server_socket_fd,
             uint8_t *buffer,
             const size_t recv_size)
{
    size_t received_size = 0;

    while (received_size < recv_size)
    {
        const size_t remaining_receive_size = recv_size - received_size;
        const ssize_t current_receive_size = recv(
            server_socket_fd, buffer + received_size, remaining_receive_size, 0);
        if (current_receive_size == 0)
        {
            LogError("recv() connection closed");
            return false;
        }
        else if (current_receive_size < 0)
        {
            LogError("recv() error: %s", STR_ERRNO);
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
        LogError("socket() error: %s", STR_ERRNO);
        return false;
    }

    struct sockaddr_in server_sockaddr;
    const in_addr_t server_addr = inet_addr(ip4_address);
    if (server_addr == (in_addr_t)-1)
    {
        close(server_socket_fd);
        LogError("inet_addr() error: %s", STR_ERRNO);
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
        LogError("connect() error: %s", STR_ERRNO);
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
        LogError("socket() error: %s", STR_ERRNO);
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
        LogError("bind() error: %s", STR_ERRNO);
        return false;
    }

    if (listen(server_socket_fd, SOMAXCONN) < 0)
    {
        close(server_socket_fd);
        LogError("listen() error: %s", STR_ERRNO);
        return false;
    }

    *server_socket_fd_ret = server_socket_fd;

    return true;
}

void TcpRunServer(const int server_socket_fd,
                  void *(*TcpRequestHandler)(void *),
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
            LogError("accept() error: %s", STR_ERRNO);
            break;
        }

        struct sockaddr_in *client_sockaddr_in = (struct sockaddr_in *)&client_sockaddr;
        char client_ip[IP_STR_LENGTH] = {0};
        inet_ntop(AF_INET, &client_sockaddr_in->sin_addr, client_ip, IP_STR_LENGTH);

        LogInfo("Got connection from %s", client_ip);

        TcpRequestHandlerCtx *ctx = malloc(sizeof(TcpRequestHandlerCtx));
        if (ctx == NULL)
        {
            close(client_socket_fd);
            LogError("Memory allocation for TcpServerHandlerCtx failed");
            exit(EXIT_FAILURE);
        }

        ctx->client_socket_fd = client_socket_fd;
        ctx->extra = ctx_extra;

        pthread_t client_thread;
        if (pthread_create(&client_thread, NULL, TcpRequestHandler, ctx))
        {
            close(client_socket_fd);
            LogError("pthread_create() error: %s", STR_ERRNO);
            continue;
        }

        pthread_detach(client_thread);
    }

    close(server_socket_fd);
}