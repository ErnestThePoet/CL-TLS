#ifndef TCP_H_
#define TCP_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>

#include "common/def.h"

bool TcpSend(const int fd, const char *buffer, const size_t send_size);
bool TcpRecv(const int fd, char *buffer, const size_t recv_size);

#endif