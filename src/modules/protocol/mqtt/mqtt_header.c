#include "mqtt_header.h"

int GetRemainingLengthByteCount(const uint32_t remaining_length)
{
    if (remaining_length <= 127U)
    {
        return 1;
    }
    else if (remaining_length <= 127U + 127U * 128)
    {
        return 2;
    }
    else if (remaining_length <= 127U + 127U * 128 + 127U * 128 * 128)
    {
        return 3;
    }
    else
    {
        return 4;
    }
}

void EncodeMqttRemainingLength(size_t remaining_length, uint8_t *out)
{
    int current_index = 0;
    while (remaining_length > 0)
    {
        uint8_t base_byte = remaining_length > 127 ? 0x80U : 0x00U;
        out[current_index++] = base_byte | (remaining_length & 0x7FU);
        remaining_length >>= 7;
    }
}

size_t DecodeMqttRemainingLength(const uint8_t *in)
{
    size_t current_byte_index = 0;
    uint8_t current_byte = in[0];
    uint32_t remaining_size = 0;
    size_t multiplier = 1;

    while (current_byte & 0x80U)
    {
        remaining_size += multiplier * (current_byte & 0x7FU);
        multiplier *= 128;
        current_byte = in[++current_byte_index];
    }

    return remaining_size + multiplier * (current_byte & 0x7FU);
}

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