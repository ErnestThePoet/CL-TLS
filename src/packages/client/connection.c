#include "connection.h"

bool ConnectToServer(
    const char *ip4_address, const int port, int *server_socket_ret)
{
    const int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1)
    {
        fprintf(stderr, "socket() error: %s\n",STR_ERRNO);
        return false;
    }

    struct sockaddr_in server_sockaddr;
    const in_addr_t server_addr = inet_addr(ip4_address);
    if (server_addr == (in_addr_t)-1)
    {
        close(server_socket);
        fprintf(stderr, "inet_addr() error: %s\n",STR_ERRNO);
        return false;
    }

    server_sockaddr.sin_addr.s_addr = server_addr;
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_port = htons(port);

    if (connect(server_socket,
                (struct sockaddr *)&server_sockaddr,
                sizeof(struct sockaddr_in)) == -1)
    {
        close(server_socket);
        fprintf(stderr, "connect() error: %s\n",STR_ERRNO);
        return false;
    }

    *server_socket_ret = server_socket;

    return true;
}

void CloseConnection(const int server_socket)
{
    close(server_socket);
}