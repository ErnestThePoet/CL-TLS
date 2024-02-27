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

#define MAX_COMMAND_LENGTH 50
#define MAX_PRINT_LENGTH 1024
#define MAX_SOCKET_BLOCK_SIZE (4 * 1024 * 1024)

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
            if (!strcmp(command, "DISCONNECT"))
            {
                uint8_t msg[2] = {0xe0, 0x00};
                TcpSend(socket_fd, msg, 2);
                TcpClose(socket_fd);
                connected = false;
                LogInfo("Disconnected");
            }
            else if (!strcmp(command, "PUBLISH"))
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
                                          GetRemainingLengthByteCount(remaining_size) +
                                          remaining_size;

                uint8_t *msg = malloc(total_size);

                msg[0] = 0x30;

                int current_index = 1;
                while (remaining_size > 0)
                {
                    uint8_t base_byte = remaining_size > 127 ? 0x80U : 0x00U;
                    msg[current_index++] = base_byte | (remaining_size & 0x7FU);
                    remaining_size >>= 7;
                }

                uint8_t counter = 0;
                for (uint32_t i = 0; i < remaining_size; i++)
                {
                    msg[current_index + i] = counter++;
                }

                if (remaining_size <= MAX_PRINT_LENGTH)
                {
                    for (uint32_t i = 0; i < remaining_size; i++)
                    {
                        printf("%02hhX ", msg[current_index + i]);
                    }
                    putchar('\n');
                }

                // Block send
                size_t sent_size = 0;
                while (sent_size < total_size)
                {
                    size_t current_send_size =
                        MIN(MAX_SOCKET_BLOCK_SIZE, total_size - sent_size);
                    if (!TcpSend(socket_fd, msg + sent_size, current_send_size))
                    {
                        TcpClose(socket_fd);
                        connected = false;
                        continue;
                    }
                    sent_size += current_send_size;
                }

                free(msg);

                LogInfo("Packet delivered");

                uint8_t receive_common_header[5] = {0};

                clock_t time_send_end = clock();
                if (!TcpRecv(socket_fd, receive_common_header, 2))
                {
                    TcpClose(socket_fd);
                    connected = false;
                    continue;
                }
                clock_t time_receive = clock();

                size_t current_byte_index = 1;
                uint8_t current_byte = receive_common_header[1];
                remaining_size = 0;
                size_t multiplier = 1;

                while (current_byte & 0x80U)
                {
                    remaining_size += multiplier * (current_byte & 0x7FU);
                    multiplier *= 128;
                    current_byte = receive_common_header[++current_byte_index];
                }

                remaining_size += multiplier * (current_byte & 0x7FU);

                LogInfo("Received %s with remaining length %u in %.03fms",
                        GetMqttMessageType(receive_common_header[0]),
                        remaining_size,
                        1000 * ((time_receive - time_send_end) / (float)CLOCKS_PER_SEC));

                msg = malloc(remaining_size);

                if (!TcpRecv(socket_fd, msg, remaining_size))
                {
                    TcpClose(socket_fd);
                    connected = false;
                    continue;
                }

                if (remaining_size <= MAX_PRINT_LENGTH)
                {
                    for (uint32_t i = 0; i < remaining_size; i++)
                    {
                        printf("%02hhX ", msg[i]);
                    }
                    putchar('\n');
                }
            }
            else
            {
                LogError("Invalid messaeg type; "
                         "currently we support PUBLISH and DISCONNECT");
                continue;
            }
        }
        else
        {
            if (strcmp(command, "CONN"))
            {
                LogError("Invalid command; type 'CONN <Server ID> <Server Port>'");
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
            clock_t time_send_end = clock();
            if (!TcpRecv(socket_fd,
                         connect_response,
                         CONNCTL_CONNECT_RESPONSE_HEADER_LENGTH))
            {
                TcpClose(socket_fd);
                continue;
            }
            clock_t time_receive = clock();

            if (connect_response[0] != CONNCTL_MSG_TYPE_CONNECT_RESPONSE)
            {
                LogError("Invalid response message type received; "
                         "expecting CONNCTL_MSG_TYPE_CONNECT_RESPONSE");
                TcpClose(socket_fd);
                continue;
            }

            if (connect_response[CONNCTL_MSG_TYPE_LENGTH] ==
                CONNCTL_CONNECT_STATUS_FAILURE)
            {
                LogError("CL-TLS Client reports connection failed");
                TcpClose(socket_fd);
                continue;
            }

            LogInfo("Successfully connected in %.03fms",
                    1000 * ((time_receive - time_send_end) / (float)CLOCKS_PER_SEC));
            connected = true;
        }
    }
}