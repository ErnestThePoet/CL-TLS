#ifndef KGC_HEADER_H_
#define KGC_HEADER_H_

#define KGC_MSG_TYPE_SERVER_REGISTER_REQUEST 0x00
#define KGC_MSG_TYPE_CLIENT_REGISTER_REQUEST 0x10
#define KGC_MSG_TYPE_SIGNATURE_DELIVERY 0x20
#define KGC_MSG_TYPE_ERROR_STOP_NOTIFY 0xF0

/******************************************************
 * Server Register Request
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Identity                            |  32B
 * ---------------------------------------
 * | Public Key Length                   |  2B
 * ---------------------------------------
 * | Public Key                          |
 * ---------------------------------------
 *
 ******************************************************/

/******************************************************
 * Client Register Request
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Identity                            |  32B
 * ---------------------------------------
 * | Public Key Length                   |  2B
 * ---------------------------------------
 * | Public Key                          |
 * ---------------------------------------
 * | Belonging Server Count              |  2B
 * ---------------------------------------
 * | Belonging Server Identities         | (32*Count)B
 * ---------------------------------------
 *
 ******************************************************/

/******************************************************
 * Signature Delivery
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 * | Signature  Length                   |  2B
 * ---------------------------------------
 * | Signature                           |
 * ---------------------------------------
 *
 ******************************************************/

/******************************************************
 * Error Stop Notify
 *
 * ---------------------------------------
 * | Message Type                        |  1B
 * ---------------------------------------
 *
 ******************************************************/

#endif