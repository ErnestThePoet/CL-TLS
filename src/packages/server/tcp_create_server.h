#ifndef TCP_CREATE_SERVER_H_
#define TCP_CREATE_SERVER_H_

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "common/def.h"

bool TcpCreateServer(int port, int *server_socket_ret);

#endif