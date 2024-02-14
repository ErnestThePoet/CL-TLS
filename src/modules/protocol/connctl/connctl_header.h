#ifndef CONNCTL_HEADER_H_
#define CONNCTL_HEADER_H_

////////// Message Types
// When a local client wants the CL-TLS proxy to
// establish a connection to a server, it sends a
// connect request to the proxy at the very beginning.
// Similar to HTTP CONNECT request that browsers send
// to HTTPS proxy servers.
// When all data have been sent, the client
// sends a disconnect request.
#define CONNCTL_MSG_TYPE_CONNECT_REQUEST 0x00
#define CONNCTL_MSG_TYPE_CONNECT_RESPONSE 0x10
#define CONNCTL_MSG_TYPE_DISCONNECT_REQUEST 0x20
#define CONNCTL_MSG_TYPE_DISCONNECT_RESPONSE 0x30

/******************************************************
 * Connect Request
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Identity                            |  32B
 * ---------------------------------------
 *
 ******************************************************/

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

/******************************************************
 * Disconnect Request
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 *
 ******************************************************/

/******************************************************
 * Disconnect Response
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Status Code                         |  1B
 * ---------------------------------------
 *
 ******************************************************/

#endif