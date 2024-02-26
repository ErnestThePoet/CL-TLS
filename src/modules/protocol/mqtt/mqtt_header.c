#include "mqtt_header.h"

const char *GetMqttMessageType(const uint8_t msg_type)
{
    switch (msg_type)
    {
    case MQTT_MSG_TYPE_CONNECT:
        return "MQTT_CONNECT";
    case MQTT_MSG_TYPE_CONNACK:
        return "MQTT_CONNACK";
    case MQTT_MSG_TYPE_PUBLISH:
        return "MQTT_PUBLISH";
    case MQTT_MSG_TYPE_PUBACK:
        return "MQTT_PUBACK";
    case MQTT_MSG_TYPE_PUBREC:
        return "MQTT_PUBREC";
    case MQTT_MSG_TYPE_PUBREL:
        return "MQTT_PUBREL";
    case MQTT_MSG_TYPE_PUBCOMP:
        return "MQTT_PUBCOMP";
    case MQTT_MSG_TYPE_SUBSCRIBE:
        return "MQTT_SUBSCRIBE";
    case MQTT_MSG_TYPE_SUBACK:
        return "MQTT_SUBACK";
    case MQTT_MSG_TYPE_UNSUBSCRIBE:
        return "MQTT_UNSUBSCRIBE";
    case MQTT_MSG_TYPE_UNSUBACK:
        return "MQTT_UNSUBACK";
    case MQTT_MSG_TYPE_PINGREQ:
        return "MQTT_PINGREQ";
    case MQTT_MSG_TYPE_PINGRESP:
        return "MQTT_PINGRESP";
    case MQTT_MSG_TYPE_DISCONNECT:
        return "MQTT_DISCONNECT";
    default:
        return "<UNKNOWN>";
    }
}