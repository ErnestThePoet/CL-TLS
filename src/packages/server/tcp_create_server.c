#include "tcp_create_server.h"

bool TcpCreateServer(int port, int *server_socket_ret)
{
    const int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        fprintf(stderr, "socket() error: %s\n",STR_ERRNO);
        return false;
    }

    struct sockaddr_in server_sockaddr;
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_addr.s_addr = INADDR_ANY;
    server_sockaddr.sin_port = htons(port);

    if (bind(server_socket,
             (struct sockaddr *)&server_sockaddr,
             sizeof(struct sockaddr_in)) < 0)
    {
        close(server_socket);
        fprintf(stderr, "bind() error: %s\n",STR_ERRNO);
        return false;
    }

    if (listen(server_socket, SOMAXCONN) < 0)
    {
        close(server_socket);
        fprintf(stderr, "listen() error: %s\n",STR_ERRNO);
        return false;
    }

    *server_socket_ret = server_socket;

    return true;
}