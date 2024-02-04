#ifndef MQTT_HEADER_H_
#define MQTT_HEADER_H_

#include <stdint.h>

typedef struct
{
    uint8_t flags;
    uint8_t remaining_length;
} MqttHeaderCommon;

#define MQTT_TYPE_CONNECT 1
#define MQTT_TYPE_CONNACK 2
#define MQTT_TYPE_PUBLISH 3
#define MQTT_TYPE_PUBACK 4
#define MQTT_TYPE_PUBREC 5
#define MQTT_TYPE_PUBREL 6
#define MQTT_TYPE_PUBCOMP 7
#define MQTT_TYPE_SUBSCRIBE 8
#define MQTT_TYPE_SUBACK 9
#define MQTT_TYPE_UNSUBSCRIBE 10
#define MQTT_TYPE_UNSUBACK 11
#define MQTT_TYPE_PINGREQ 12
#define MQTT_TYPE_PINGRESP 13
#define MQTT_TYPE_DISCONNECT 14

#endif