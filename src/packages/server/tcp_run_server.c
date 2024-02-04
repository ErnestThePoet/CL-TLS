#include "tcp_run_server.h"

void TcpRunServer(const int server_socket)
{
    struct sockaddr_in client_sockaddr;
    socklen_t sockaddr_size = sizeof(struct sockaddr_in);

    while (true)
    {
        int client_socket = accept(
            server_socket, (struct sockaddr *)&client_sockaddr, &sockaddr_size);
        if (client_socket == -1)
        {
            close(client_socket);
            PRINT_ERROR("accept()", strerror(errno));
            continue;
        }

        pthread_t client_thread;
        if (pthread_create(&client_thread, NULL, TcpHandleRequest, &client_socket))
        {
            close(client_socket);
            PRINT_ERROR("pthread_create()", strerror(errno));
            continue;
        }

        pthread_detach(client_thread);
    }

    close(server_socket);
}