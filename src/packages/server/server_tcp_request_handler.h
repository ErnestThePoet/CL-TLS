#ifndef SERVER_TCP_REQUEST_HANDLER_H_
#define SERVER_TCP_REQUEST_HANDLER_H_

#include <stdio.h>

#include <common/def.h>

#include <openssl/evp.h>

void *ServerTcpRequestHandler(void *arg);

#endif