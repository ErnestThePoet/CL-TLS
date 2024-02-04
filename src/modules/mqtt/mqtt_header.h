#ifndef MQTT_HEADER_H_
#define MQTT_HEADER_H_

#include <stdint.h>

typedef struct{
    uint8_t flags;
    uint8_t remaining_length;
} MqttHeaderCommon;

#endif