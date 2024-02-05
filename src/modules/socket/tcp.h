#ifndef TCP_H_
#define TCP_H_

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "common/def.h"

bool TcpSend(const int socket_fd, const char *buffer, const size_t send_size);
bool TcpRecv(const int socket_fd, char *buffer, const size_t recv_size);

bool TcpConnectToServer(
    const char *ip4_address, const uint16_t port, int *socket_fd_ret);
void TcpClose(const int socket_fd);

bool TcpCreateServer(uint16_t port, int *socket_fd_ret);

void TcpRunServer(const int socket_fd, void *(*TcpHandleRequest)(void *));

#endif