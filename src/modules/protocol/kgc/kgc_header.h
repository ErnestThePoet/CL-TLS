#ifndef KGC_HEADER_H_
#define KGC_HEADER_H_

#include <common/def.h>
#include <protocol/cltls/cltls_header.h>

////////// Message Types
#define KGC_MSG_TYPE_REGISTER_REQUEST 0x00
#define KGC_MSG_TYPE_RESIGTER_RESPONSE 0x10
#define KGC_MSG_TYPE_ADD_CLIENT_REQUEST 0x20
#define KGC_MSG_TYPE_ADD_CLIENT_RESPONSE 0x30

////////// Entity Types
#define KGC_ENTITY_TYPE_CLIENT 0x00
#define KGC_ENTITY_TYPE_SERVER 0x10

////////// Register Response Status Codes
#define KGC_REGISTER_STATUS_SUCCESS 0x00
#define KGC_REGISTER_STATUS_FAILURE 0xF0

////////// Add Client Response Status Codes
#define KGC_ADD_CLIENT_STATUS_SUCCESS 0x00
#define KGC_ADD_CLIENT_STATUS_FAILURE 0xF0

#define KGC_MSG_TYPE_LENGTH 1
#define KGC_ENTITY_TYPE_LENGTH 1
#define KGC_BELONGING_SERVER_COUNT_LENGTH 2
#define KGC_BELONGING_SERVER_PORT_LENGTH 2
#define KGC_STATUS_CODE_LENGTH 1

/******************************************************
 * Register Request(Server)
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Entity Type                         |  1B
 * ---------------------------------------
 * | Identity                            |  32B
 * ---------------------------------------
 * | Public Key                          |  32B
 * ---------------------------------------
 *
 ******************************************************/

#define KGC_REGISTER_REQUEST_SERVER_HEADER_LENGTH \
    (KGC_MSG_TYPE_LENGTH +                        \
     KGC_ENTITY_TYPE_LENGTH +                     \
     ENTITY_IDENTITY_LENGTH +                     \
     CLTLS_ENTITY_PUBLIC_KEY_LENGTH)

/******************************************************
 * Register Request(Client)
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Entity Type                         |  1B
 * ---------------------------------------
 * | Identity                            |  32B
 * ---------------------------------------
 * | Public Key                          |
 * ---------------------------------------
 * | Belonging Server Count              |  2B
 * ---------------------------------------
 * | Belonging Server Identities & Ports | ((32+2)*Count)B
 * ---------------------------------------
 *
 ******************************************************/

/******************************************************
 * Register Response(Success)
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Status Code                         |  1B
 * ---------------------------------------
 * | Signature                           |  64B
 * ---------------------------------------
 *
 ******************************************************/

#define KGC_REGISTER_RESPONSE_SUCCESS_HEADER_LENGTH \
    (KGC_MSG_TYPE_LENGTH +                          \
     KGC_STATUS_CODE_LENGTH +                       \
     CLTLS_ENTITY_PUBLIC_KEY_SIGNATURE_LENGTH)

/******************************************************
 * Register Response(Failure)
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Status Code                         |  1B
 * ---------------------------------------
 *
 ******************************************************/

#define KGC_REGISTER_RESPONSE_FAILURE_HEADER_LENGTH \
    (KGC_MSG_TYPE_LENGTH +                          \
     KGC_STATUS_CODE_LENGTH)

/******************************************************
 * Add Client Request
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Identity                            |  32B
 * ---------------------------------------
 *
 ******************************************************/

#define KGC_ADD_CLIENT_REQUEST_HEADER_LENGTH \
    (KGC_MSG_TYPE_LENGTH +                   \
     ENTITY_IDENTITY_LENGTH)

/******************************************************
 * Add Client Response
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Status Code                         |  1B
 * ---------------------------------------
 *
 ******************************************************/

#define KGC_ADD_CLIENT_RESPONSE_HEADER_LENGTH \
    (KGC_MSG_TYPE_LENGTH +                    \
     KGC_STATUS_CODE_LENGTH)

#endif