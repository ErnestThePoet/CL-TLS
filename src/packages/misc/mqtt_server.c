#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <common/def.h>
#include <util/log.h>
#include <util/util.h>

#include <socket/tcp/tcp.h>
#include <protocol/connctl/connctl_header.h>
#include <protocol/mqtt/mqtt_header.h>

#define MAX_FULL_PRINT_LENGTH 1024
#define HEAD_TAIL_PRINT_LENGTH 16
#define MAX_SOCKET_BLOCK_SIZE (4 * 1024 * 1024)

void PrintBytes(const uint8_t *data, const size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        printf("%02hhX ", data[i]);
    }
    putchar('\n');
}

void PrintHeadTailBytes(const uint8_t *data,
                        const size_t length,
                        const size_t print_count)
{
    printf("First %zu bytes:\n", print_count);
    for (size_t i = 0; i < print_count; i++)
    {
        printf("%02hhX ", data[i]);
    }
    putchar('\n');

    printf("Last %zu bytes:\n", print_count);
    for (size_t i = 0; i < print_count; i++)
    {
        printf("%02hhX ", data[i + length - print_count + i]);
    }
    putchar('\n');
}

#define MQTT_SERVER_CLOSE_FREE_RETURN \
    do                                \
    {                                 \
        TcpClose(socket_fd);          \
        free(arg);                    \
        return NULL;                  \
    } while (false)

void *MqttServerTcpRequestHandler(void *arg)
{
    const TcpRequestHandlerCtx *ctx = (const TcpRequestHandlerCtx *)arg;
    const int socket_fd = ctx->client_socket_fd;

    while (true)
    {
        uint8_t receive_fixed_header[MQTT_FIXED_HEADER_LENGTH] = {0};

        if (!TcpRecv(socket_fd, receive_fixed_header, 2))
        {
            MQTT_SERVER_CLOSE_FREE_RETURN;
        }

        uint8_t current_byte = receive_fixed_header[1];
        uint32_t remaining_size = 0;
        size_t multiplier = 1;

        while (current_byte & 0x80U)
        {
            remaining_size += multiplier * (current_byte & 0x7FU);
            multiplier *= 128;
            if (!TcpRecv(socket_fd,
                         &current_byte,
                         1))
            {
                MQTT_SERVER_CLOSE_FREE_RETURN;
            }
        }

        remaining_size += multiplier * (current_byte & 0x7FU);

        uint8_t msg_type = MQTT_MSG_TYPE(receive_fixed_header[0]);
        LogInfo("Received %s (0x%02hhX) with remaining length %u",
                GetMqttMessageType(msg_type),
                msg_type,
                remaining_size);

        uint8_t *msg = malloc(remaining_size == 0 ? 1 : remaining_size);
        if (msg == NULL)
        {
            LogError("Memory allocation for |msg| failed");
            exit(EXIT_FAILURE);
        }

        if (!TcpRecv(socket_fd, msg, remaining_size))
        {
            free(msg);
            MQTT_SERVER_CLOSE_FREE_RETURN;
        }

        if (remaining_size <= MAX_FULL_PRINT_LENGTH)
        {
            PrintBytes(msg, remaining_size);
        }
        else
        {
            PrintHeadTailBytes(msg, remaining_size, HEAD_TAIL_PRINT_LENGTH);
        }

        if (msg_type == MQTT_MSG_TYPE_DISCONNECT)
        {
            free(msg);
            break;
        }

        // Send back a PUBLISH with same length
        const size_t total_size = 1 +
                                  GetMqttRemainingLengthByteCount(remaining_size) +
                                  remaining_size;

        msg = realloc(msg, total_size);
        if (msg == NULL)
        {
            LogError("Memory reallocation for |msg| failed");
            exit(EXIT_FAILURE);
        }

        msg[0] = 0x30;

        const size_t rl_byte_count = EncodeMqttRemainingLength(
            remaining_size, msg + 1);

        uint8_t counter = 0xFF;
        for (uint32_t i = 0; i < remaining_size; i++)
        {
            msg[1 + rl_byte_count + i] = counter--;
        }

        // Block send
        size_t sent_size = 0;
        while (sent_size < total_size)
        {
            size_t current_send_size =
                MIN(MAX_SOCKET_BLOCK_SIZE, total_size - sent_size);
            if (!TcpSend(socket_fd, msg + sent_size, current_send_size))
            {
                free(msg);
                MQTT_SERVER_CLOSE_FREE_RETURN;
            }
            sent_size += current_send_size;
        }

        LogInfo("PUBLISH Message delivered");

        if (remaining_size <= MAX_FULL_PRINT_LENGTH)
        {
            PrintBytes(msg + 1 + rl_byte_count, remaining_size);
        }
        else
        {
            PrintHeadTailBytes(msg + 1 + rl_byte_count,
                               remaining_size,
                               HEAD_TAIL_PRINT_LENGTH);
        }
    }

    LogInfo("Disconnected");

    MQTT_SERVER_CLOSE_FREE_RETURN;
}

int main(int argc, char *argv[])
{
    kLogLevel = LOG_LEVEL_INFO;

    if (argc != 2)
    {
        LogError("Invalid arguments");
        fputs("Usage: cltls_misc_mqtt_server <Listen Port>\n", stderr);
        return EXIT_FAILURE;
    }

    uint16_t port = atoi(argv[1]);

    int server_socket_fd = 0;
    if (!TcpCreateServer(port, &server_socket_fd))
    {
        return EXIT_FAILURE;
    }

    TcpRunServer(server_socket_fd, MqttServerTcpRequestHandler, NULL);

    return EXIT_SUCCESS;
}