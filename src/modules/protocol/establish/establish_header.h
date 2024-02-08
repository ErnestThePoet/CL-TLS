#ifndef ESTABLISH_HEADER_H_
#define ESTABLISH_HEADER_H_

// When a local client wants the CL-TLS proxy to
// establish a connection to a server, it sends an
// establish request to the proxy at the very beginning.
// Similar to HTTP CONNECT request that browsers send
// to HTTPS proxy servers.

#define ESTABLISH_MSG_TYPE_REQUEST 0x00
#define ESTABLISH_MSG_TYPE_RESONSE 0x10

/******************************************************
 * Establish Request
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Identity Length                     |  2B
 * ---------------------------------------
 * | Identity                            |
 * ---------------------------------------
 *
 ******************************************************/

#endif