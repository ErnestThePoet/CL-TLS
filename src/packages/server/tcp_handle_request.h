#ifndef TCP_HANDLE_REQUEST_H_
#define TCP_HANDLE_REQUEST_H_

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "common/def.h"

void* TcpHandleRequest(void *arg);

#endif