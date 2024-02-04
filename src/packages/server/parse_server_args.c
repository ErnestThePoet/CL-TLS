#include "parse_server_args.h"

bool ParseServerArgs(
    const int argc, char *argv[], ServerArgs *server_args_ret)
{
    if (argc <= 1)
    {
        fprintf(stderr, "ParseServerArgs() error: Too few command line arguments\n");
        return false;
    }

    if (!strcmp(argv[0], "--help"))
    {
        return false;
    }

    ParseState parse_state = PARSE_STATE_EXPECT_OPTION_NAME;
    OptionName current_option_name = OPTION_NAME_NONE;

    int parsed_mandatory_option_count = 0;

    for (int i = 1; i < argc; i++)
    {
        switch (parse_state)
        {
        case PARSE_STATE_EXPECT_OPTION_NAME:
            if (!strcmp(argv[i], "--port"))
            {
                parse_state = PARSE_STATE_EXPECT_OPTION_VALUE;
                current_option_name = OPTION_NAME_PORT;
            }
            else if (!strcmp(argv[i], "--forward"))
            {
                parse_state = PARSE_STATE_EXPECT_OPTION_VALUE;
                current_option_name = OPTION_NAME_FORWARD;
            }
            else if (!strcmp(argv[i], "--log"))
            {
                parse_state = PARSE_STATE_EXPECT_OPTION_VALUE;
                current_option_name = OPTION_NAME_LOG;
            }
            else
            {
                fprintf(stderr,
                        "ParseServerArgs() error: Unrecognized option '%s'\n",
                        argv[i]);
                return false;
            }
            break;
        case PARSE_STATE_EXPECT_OPTION_VALUE:
            switch (current_option_name)
            {
            case OPTION_NAME_NONE:
                break;
            case OPTION_NAME_PORT:
                char *listen_port_parse_end = NULL;
                unsigned long parsed_listen_port = strtoul(argv[i], &listen_port_parse_end, 10);
                if (listen_port_parse_end != argv[i] + strlen(argv[i]) ||
                    parsed_listen_port > 65535)
                {
                    fprintf(stderr,
                            "ParseServerArgs() error: Invalid port number '%s'\n",
                            argv[i]);
                    return false;
                }

                server_args_ret->listen_port = parsed_listen_port;

                parse_state = PARSE_STATE_EXPECT_OPTION_NAME;

                parsed_mandatory_option_count++;

                break;
            case OPTION_NAME_FORWARD:
                const size_t forward_length = strlen(argv[i]);
                for (int j = 0; j < forward_length; j++)
                {
                    if (j >= 50)
                    {
                        fprintf(stderr,
                                "ParseServerArgs() error: Forward IP address too long\n");
                        return false;
                    }

                    if (argv[i][j] == ':')
                    {
                        server_args_ret->forward_ip[j] = '\0';

                        if (j == forward_length - 1)
                        {
                            fprintf(stderr,
                                    "ParseServerArgs() error: Forward port not provided\n");
                            return false;
                        }

                        char *forward_port_start = argv[i] + j + 1;
                        char *forward_port_parse_end = NULL;
                        unsigned long parsed_forward_port = strtoul(forward_port_start, &forward_port_parse_end, 10);
                        if (forward_port_parse_end != argv[i] + forward_length ||
                            parsed_forward_port > 65535)
                        {
                            fprintf(stderr,
                                    "ParseServerArgs() error: Invalid forward port number '%s'\n",
                                    forward_port_start);
                            return false;
                        }

                        server_args_ret->forward_port = parsed_forward_port;
                    }
                    else
                    {
                        server_args_ret->forward_ip[j] = argv[i][j];
                    }
                }

                parse_state = PARSE_STATE_EXPECT_OPTION_NAME;

                parsed_mandatory_option_count++;

                break;
            case OPTION_NAME_LOG:
                if (!strcmp(argv[i], "ERROR"))
                {
                    server_args_ret->log_level = LOG_LEVEL_ERROR;
                }
                else if (!strcmp(argv[i], "WARN"))
                {
                    server_args_ret->log_level = LOG_LEVEL_WARN;
                }
                else if (!strcmp(argv[i], "INFO"))
                {
                    server_args_ret->log_level = LOG_LEVEL_INFO;
                }
                else
                {
                    fprintf(stderr,
                            "ParseServerArgs() error: Unrecognized log level '%s'\n",
                            argv[i]);
                    return false;
                }

                parse_state = PARSE_STATE_EXPECT_OPTION_NAME;

                break;
            }
            break;
        }
    }

    if (parse_state != PARSE_STATE_EXPECT_OPTION_NAME)
    {
        fprintf(stderr,
                "ParseServerArgs() error: Missing option value\n");
        return false;
    }

    if (parsed_mandatory_option_count != kMandatoryOptionCount)
    {
        fprintf(stderr,
                "ParseServerArgs() error: Missing or duplicate mandatory command line options\n");
        return false;
    }

    return true;
}