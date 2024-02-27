#ifndef MQTT_HEADER_H_
#define MQTT_HEADER_H_

#include <stdint.h>

/**************************************************************
 * MQTT Fixed Header
 * See https://public.dhe.ibm.com/software/dw/webservices/ws-mqtt/mqtt-v3r1.html
 * for reference
 *
 * ---------------------------------------------------------
 * | bit | 7 | 6 | 5 | 4 |     3     |  2  |  1  |    0    |
 * ---------------------------------------------------------
 * | 1B  | Message Type  | DUP Flag  | QOS Level | RETAIN  |
 * ---------------------------------------------------------
 * | 1B  | Remaining Length (Uses variable length encoding |
 * |     | scheme; See reference for explanation)          |
 * ---------------------------------------------------------
 *
 **************************************************************/

#define MQTT_FIXED_HEADER_LENGTH 2

#define MQTT_MSG_TYPE_CONNECT 1
#define MQTT_MSG_TYPE_CONNACK 2
#define MQTT_MSG_TYPE_PUBLISH 3
#define MQTT_MSG_TYPE_PUBACK 4
#define MQTT_MSG_TYPE_PUBREC 5
#define MQTT_MSG_TYPE_PUBREL 6
#define MQTT_MSG_TYPE_PUBCOMP 7
#define MQTT_MSG_TYPE_SUBSCRIBE 8
#define MQTT_MSG_TYPE_SUBACK 9
#define MQTT_MSG_TYPE_UNSUBSCRIBE 10
#define MQTT_MSG_TYPE_UNSUBACK 11
#define MQTT_MSG_TYPE_PINGREQ 12
#define MQTT_MSG_TYPE_PINGRESP 13
#define MQTT_MSG_TYPE_DISCONNECT 14

#define MQTT_MSG_TYPE(BYTE1) ((BYTE1) >> 4)

int GetRemainingLengthByteCount(const uint32_t remaining_length);
const char *GetMqttMessageType(const uint8_t msg_type);

#endif