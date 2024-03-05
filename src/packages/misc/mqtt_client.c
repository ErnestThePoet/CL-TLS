#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#include <common/def.h>
#include <util/log.h>
#include <util/util.h>

#include <socket/tcp/tcp.h>
#include <protocol/connctl/connctl_header.h>
#include <protocol/mqtt/mqtt_header.h>

#define MAX_COMMAND_LENGTH 50
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
        printf("%02hhX ", data[length - print_count + i]);
    }
    putchar('\n');
}

int main(int argc, char *argv[])
{
    kLogLevel = LOG_LEVEL_INFO;

    if (argc != 3)
    {
        LogError("Invalid arguments");
        fputs("Usage: cltls_misc_mqtt_client <CLTLS Client IP> <CLTLS Client Port>\n", stderr);
        return EXIT_FAILURE;
    }

    uint16_t port = atoi(argv[2]);

    int socket_fd = 0;
    if (!TcpConnectToServer(argv[1], port, &socket_fd))
    {
        return EXIT_FAILURE;
    }

    bool connected = false;
    char command[MAX_COMMAND_LENGTH] = {0};

    while (true)
    {
        if (scanf("%s", command) != 1)
        {
            LogError("Failed to read command");
            continue;
        }

        if (connected)
        {
            // All MQTT Packets contain random bytes after remaining length
            if (!strcmp(command, "DISCONNECT") || !strcmp(command, "D"))
            {
                uint8_t msg[2] = {0xe0, 0x00};
                TcpSend(socket_fd, msg, 2);
                connected = false;
                LogInfo("Disconnected");
            }
            else if (!strcmp(command, "PUBLISH") || !strcmp(command, "P"))
            {
                uint32_t remaining_size = 0;
                const uint32_t max_remaining_size = 256U * 1024 * 1024 - 1;
                if (scanf("%u", &remaining_size) != 1)
                {
                    LogError("Invalid remaining size");
                    continue;
                }

                if (remaining_size > max_remaining_size)
                {
                    LogError("Remaining size must be <= %u (256MB-1)",
                             max_remaining_size);
                    continue;
                }

                const size_t total_size = 1 +
                                          GetMqttRemainingLengthByteCount(remaining_size) +
                                          remaining_size;

                uint8_t *msg = malloc(total_size);
                if (msg == NULL)
                {
                    LogError("Memory allocation for |msg| failed");
                    exit(EXIT_FAILURE);
                }

                msg[0] = 0x30;

                const size_t rl_byte_count = EncodeMqttRemainingLength(
                    remaining_size, msg + 1);

                uint8_t counter = 0;
                for (uint32_t i = 0; i < remaining_size; i++)
                {
                    msg[1 + rl_byte_count + i] = counter++;
                }

                // Block send
                size_t sent_size = 0;
                bool should_continue = false;

                while (sent_size < total_size)
                {
                    size_t current_send_size =
                        MIN(MAX_SOCKET_BLOCK_SIZE, total_size - sent_size);
                    if (!TcpSend(socket_fd, msg + sent_size, current_send_size))
                    {
                        TcpClose(socket_fd);
                        free(msg);
                        connected = false;
                        should_continue = true;
                        break;
                    }
                    sent_size += current_send_size;
                }

                if (should_continue)
                {
                    free(msg);
                    continue;
                }

                LogInfo("%s (0x%02hhX) with remaining length %u delivered",
                        GetMqttMessageType(MQTT_MSG_TYPE_PUBLISH),
                        MQTT_MSG_TYPE_PUBLISH,
                        remaining_size);

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

                uint8_t receive_fixed_header[MQTT_FIXED_HEADER_LENGTH] = {0};

                if (!TcpRecv(socket_fd, receive_fixed_header, 2))
                {
                    TcpClose(socket_fd);
                    free(msg);
                    connected = false;
                    continue;
                }

                uint8_t current_byte = receive_fixed_header[1];
                remaining_size = 0;
                size_t multiplier = 1;

                should_continue = false;
                while (current_byte & 0x80U)
                {
                    remaining_size += multiplier * (current_byte & 0x7FU);
                    multiplier *= 128;
                    if (!TcpRecv(socket_fd,
                                 &current_byte,
                                 1))
                    {
                        TcpClose(socket_fd);
                        free(msg);
                        connected = false;
                        should_continue = true;
                        break;
                    }
                }

                remaining_size += multiplier * (current_byte & 0x7FU);

                if (should_continue)
                {
                    continue;
                }

                LogInfo("Received %s (0x%02hhX) with remaining length %u",
                        GetMqttMessageType(MQTT_MSG_TYPE(receive_fixed_header[0])),
                        MQTT_MSG_TYPE(receive_fixed_header[0]),
                        remaining_size);

                msg = realloc(msg, remaining_size == 0 ? 1 : remaining_size);
                if (msg == NULL)
                {
                    LogError("Memory reallocation for |msg| failed");
                    exit(EXIT_FAILURE);
                }

                if (!TcpRecv(socket_fd, msg, remaining_size))
                {
                    TcpClose(socket_fd);
                    free(msg);
                    connected = false;
                    continue;
                }

                if (remaining_size <= MAX_FULL_PRINT_LENGTH)
                {
                    PrintBytes(msg, remaining_size);
                }
                else
                {
                    PrintHeadTailBytes(msg, remaining_size, HEAD_TAIL_PRINT_LENGTH);
                }
            }
            else
            {
                LogError("Invalid message type '%s'; "
                         "currently we support PUBLISH(P) and DISCONNECT(D)",
                         command);
                continue;
            }
        }
        else
        {
            if (strcmp(command, "CONN"))
            {
                LogError("Invalid command '%s'; type 'CONN <Server ID> <Server Port>'",
                         command);
                continue;
            }

            char server_id_hex[ENTITY_IDENTITY_HEX_STR_LENGTH] = {0};
            uint16_t server_port = 0;
            if (scanf("%s %hu", server_id_hex, &server_port) != 2)
            {
                LogError("Invalid server ID or server port");
                continue;
            }

            uint8_t connect_request[CONNCTL_CONNECT_REQUEST_HEADER_LENGTH] = {0};
            connect_request[0] = CONNCTL_MSG_TYPE_CONNECT_REQUEST;
            if (!Hex2Bin(server_id_hex,
                         connect_request + CONNCTL_MSG_TYPE_LENGTH,
                         ENTITY_IDENTITY_LENGTH))
            {
                LogError("Invalid server ID");
                continue;
            }

            *((uint16_t *)(connect_request +
                           CONNCTL_MSG_TYPE_LENGTH +
                           ENTITY_IDENTITY_LENGTH)) = htons(server_port);

            if (!TcpSend(socket_fd,
                         connect_request,
                         CONNCTL_CONNECT_REQUEST_HEADER_LENGTH))
            {
                TcpClose(socket_fd);
                continue;
            }

            uint8_t connect_response[CONNCTL_CONNECT_RESPONSE_HEADER_LENGTH] = {0};

            if (!TcpRecv(socket_fd,
                         connect_response,
                         CONNCTL_CONNECT_RESPONSE_HEADER_LENGTH))
            {
                TcpClose(socket_fd);
                continue;
            }

            if (connect_response[0] != CONNCTL_MSG_TYPE_CONNECT_RESPONSE)
            {
                LogError("Invalid response message type (0x%02hhX) received; "
                         "expecting CONNCTL_MSG_TYPE_CONNECT_RESPONSE (0x%02hhX)",
                         connect_response[0],
                         CONNCTL_MSG_TYPE_CONNECT_RESPONSE);
                TcpClose(socket_fd);
                continue;
            }

            if (connect_response[CONNCTL_MSG_TYPE_LENGTH] ==
                CONNCTL_CONNECT_STATUS_FAILURE)
            {
                LogError("CL-TLS Client reports connection failed");
                continue;
            }

            LogSuccess("Successfully connected");

            connected = true;
        }
    }

    return EXIT_SUCCESS;
}