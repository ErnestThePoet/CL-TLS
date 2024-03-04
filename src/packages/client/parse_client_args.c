#include "parse_client_args.h"

void ParseClientArgs(
    const int argc, char *argv[], ClientArgs *client_args_ret)
{
    int register_client = 0;
    const char *belonging_servers_file_path = NULL;
    int listen_port = -1;
    const char *log_level = NULL;
    const char *config_file_path = NULL;

    const char *usages[] = {
        "cltls_client [options]",
        NULL};

    struct argparse_option options[] =
        {
            OPT_HELP(),
            OPT_GROUP("Register server"),
            OPT_BOOLEAN('r', "register", &register_client, "register the client from KGC", NULL, 0, 0),
            OPT_GROUP("Mandatory options to register client"),
            OPT_STRING('\0', "bs", &belonging_servers_file_path, "belonging servers file path", NULL, 0, 0),
            OPT_GROUP("Mandatory options to run client"),
            OPT_INTEGER('p', "port", &listen_port, "listen port", NULL, 0, 0),
            OPT_GROUP("Optional options"),
            OPT_STRING('l', "log", &log_level, "log level(ERROR|WARN|INFO), defaults to 'INFO'", NULL, 0, 0),
            OPT_STRING('c', "config", &config_file_path, "server config file path, defaults to 'config.conf'", NULL, 0, 0),
            OPT_END(),
        };

    struct argparse arg_parse;
    argparse_init(&arg_parse, options, usages, 0);
    argparse_describe(&arg_parse,
                      "\nThe client implementation of CL-TLS.",
                      NULL);
    argparse_parse(&arg_parse, argc, (const char **)argv);

    if (log_level == NULL || !strcmp(log_level, "INFO"))
    {
        kLogLevel = LOG_LEVEL_INFO;
    }
    else if (!strcmp(log_level, "WARN"))
    {
        kLogLevel = LOG_LEVEL_WARN;
    }
    else if (!strcmp(log_level, "ERROR"))
    {
        kLogLevel = LOG_LEVEL_ERROR;
    }
    else
    {
        PRINT_ERROR_INVALID_OPTION_VALUE("%s", log_level, "'log'('l')");
    }

    if (config_file_path == NULL)
    {
        strcpy(client_args_ret->config_file_path, "config.conf");
    }
    else if (strlen(config_file_path) >= MAX_PATH_LENGTH)
    {
        PRINT_ERROR_INVALID_OPTION_VALUE("%s", config_file_path, "'config'('c')");
    }
    else
    {
        strcpy(client_args_ret->config_file_path, config_file_path);
    }

    if (register_client)
    {
        client_args_ret->register_client = true;

        if (belonging_servers_file_path == NULL)
        {
            PRINT_ERROR_REQUIRED_OPTION_NOT_PROVIDED("'bs'");
        }
        else if (strlen(belonging_servers_file_path) >= MAX_PATH_LENGTH)
        {
            PRINT_ERROR_INVALID_OPTION_VALUE(
                "%s", belonging_servers_file_path, "'bs'");
        }
        else
        {
            strcpy(client_args_ret->belonging_servers_file_path,
                   belonging_servers_file_path);
        }
        return;
    }
    else
    {
        client_args_ret->register_client = false;
    }

    if (listen_port == -1)
    {
        PRINT_ERROR_REQUIRED_OPTION_NOT_PROVIDED("'port'('p')");
    }
    else if (listen_port < 0 || listen_port > 65535)
    {
        PRINT_ERROR_INVALID_OPTION_VALUE("%d", listen_port, "'port'('p')");
    }
    else
    {
        client_args_ret->listen_port = listen_port;
    }
}