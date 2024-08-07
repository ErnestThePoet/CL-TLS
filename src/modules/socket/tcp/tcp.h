#ifndef TCP_H_
#define TCP_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <common/def.h>
#include <util/log.h>

typedef struct
{
    int client_socket_fd;
    void *extra;
} TcpRequestHandlerCtx;

bool TcpSend(const int client_socket_fd,
             const uint8_t *buffer,
             const size_t send_size);
bool TcpRecv(const int server_socket_fd,
             uint8_t *buffer,
             const size_t recv_size);

bool TcpConnectToServer(const char *ip4_address,
                        const uint16_t port,
                        int *server_socket_fd_ret);

void TcpClose(const int socket_fd);

bool TcpCreateServer(uint16_t port,
                     int *server_socket_fd_ret);

// TcpHandleRequest is responsible for freeing the TcpServerHandlerCtx* arg
// and closing client_socket_fd.
void TcpRunServer(const int server_socket_fd,
                  void *(*TcpRequestHandler)(void *),
                  void *ctx_extra);

#endif