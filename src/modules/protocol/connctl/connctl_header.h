#ifndef CONNCTL_HEADER_H_
#define CONNCTL_HEADER_H_

#include <common/def.h>

////////// Message Types
// When a local client wants the CL-TLS proxy to
// establish a connection to a server, it sends a
// connect request to the proxy at the very beginning.
// Similar to HTTP CONNECT request that browsers send
// to HTTPS proxy servers.
#define CONNCTL_MSG_TYPE_CONNECT_REQUEST 0x00
#define CONNCTL_MSG_TYPE_CONNECT_RESPONSE 0x10

#define CONNCTL_CONNECT_STATUS_SUCCESS 0x00
#define CONNCTL_CONNECT_STATUS_FAILURE 0xF0

#define CONNCTL_MSG_TYPE_LENGTH 1
#define CONNCTL_PORT_LENGTH 2
#define CONNCTL_STATUS_CODE_LENGTH 1

/******************************************************
 * Connect Request
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Identity                            |  8B
 * ---------------------------------------
 * | Port                                |  2B
 * ---------------------------------------
 *
 ******************************************************/

#define CONNCTL_CONNECT_REQUEST_HEADER_LENGTH \
    (CONNCTL_MSG_TYPE_LENGTH + ENTITY_IDENTITY_LENGTH + CONNCTL_PORT_LENGTH)

/******************************************************
 * Connect Response
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Status Code                         |  1B
 * ---------------------------------------
 *
 ******************************************************/

#define CONNCTL_CONNECT_RESPONSE_HEADER_LENGTH \
    (CONNCTL_MSG_TYPE_LENGTH + CONNCTL_STATUS_CODE_LENGTH)

#endif