#ifndef TCP_RUN_SERVER_H_
#define TCP_RUN_SERVER_H_

#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "common/def.h"
#include "tcp_handle_request.h"

void TcpRunServer(const int server_socket);

#endif