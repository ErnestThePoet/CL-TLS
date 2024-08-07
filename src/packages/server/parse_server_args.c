#include "parse_server_args.h"

void ParseServerArgs(
    const int argc, char *argv[], ServerArgs *server_args_ret)
{
    int register_server = 0;
    const char *mode = NULL;
    int listen_port = -1;
    const char *forward_ip = NULL;
    int forward_port = -1;
    const char *log_level = NULL;
    const char *preferred_cipher_suite = NULL;
    const char *config_file_path = NULL;
    int print_timing = 0;

    const char *usages[] = {
        "cltls_server [options]",
        NULL};

    struct argparse_option options[] =
        {
            OPT_HELP(),
            OPT_GROUP("Register server"),
            OPT_BOOLEAN('r', "register", &register_server, "register the server from KGC", NULL, 0, 0),
            OPT_GROUP("Mandatory options to run server"),
            OPT_STRING('m', "mode", &mode, "server mode(KGC|PROXY)", NULL, 0, 0),
            OPT_GROUP("Options required in PROXY mode"),
            OPT_INTEGER('p', "port", &listen_port, "listen port", NULL, 0, 0),
            OPT_STRING('\0', "fwd-ip", &forward_ip, "proxy forward ip", NULL, 0, 0),
            OPT_INTEGER('\0', "fwd-port", &forward_port, "proxy forward port", NULL, 0, 0),
            OPT_GROUP("Optional options"),
            OPT_STRING('l', "log", &log_level, "log level(ERROR|WARN|INFO), defaults to 'INFO'", NULL, 0, 0),
            OPT_STRING('\0', "cipher", &preferred_cipher_suite, "preferred cipher suite(ASCON128A_ASCONHASHA|ASCON128A_SHA256|AES128GCM_ASCONHASHA|AES128GCM_SHA256), defaults to 'ASCON128A_ASCONHASHA'", NULL, 0, 0),
            OPT_STRING('c', "config", &config_file_path, "server config file path, defaults to 'config.conf'", NULL, 0, 0),
            OPT_BOOLEAN('t', "timing", &print_timing, "print handshake and application service timing", NULL, 0, 0),
            OPT_END(),
        };

    struct argparse arg_parse;
    argparse_init(&arg_parse, options, usages, 0);
    argparse_describe(&arg_parse,
                      "\nThe server implementation of CL-TLS which can run as a KGC or proxy.",
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

    if (preferred_cipher_suite == NULL ||
        !strcmp(preferred_cipher_suite, "ASCON128A_ASCONHASHA"))
    {
        server_args_ret->preferred_cipher_suite = CLTLS_CIPHER_ASCON128A_ASCONHASHA;
    }
    else if (!strcmp(preferred_cipher_suite, "ASCON128A_SHA256"))
    {
        server_args_ret->preferred_cipher_suite = CLTLS_CIPHER_ASCON128A_SHA256;
    }
    else if (!strcmp(preferred_cipher_suite, "AES128GCM_ASCONHASHA"))
    {
        server_args_ret->preferred_cipher_suite = CLTLS_CIPHER_AES128GCM_ASCONHASHA;
    }
    else if (!strcmp(preferred_cipher_suite, "AES128GCM_SHA256"))
    {
        server_args_ret->preferred_cipher_suite = CLTLS_CIPHER_AES128GCM_SHA256;
    }
    else
    {
        PRINT_ERROR_INVALID_OPTION_VALUE("%s", preferred_cipher_suite, "'cipher'");
    }

    if (config_file_path == NULL)
    {
        strcpy(server_args_ret->config_file_path, "config.conf");
    }
    else if (strlen(config_file_path) >= MAX_PATH_LENGTH)
    {
        PRINT_ERROR_INVALID_OPTION_VALUE("%s", config_file_path, "'config'('c')");
    }
    else
    {
        strcpy(server_args_ret->config_file_path, config_file_path);
    }

    kPrintTiming = (bool)print_timing;

    if (register_server)
    {
        server_args_ret->register_server = true;
        return;
    }
    else
    {
        server_args_ret->register_server = false;
    }

    if (mode == NULL)
    {
        PRINT_ERROR_REQUIRED_OPTION_NOT_PROVIDED("'mode'('m')");
    }
    else if (!strcmp(mode, "KGC"))
    {
        server_args_ret->mode = SERVER_MODE_KGC;
    }
    else if (!strcmp(mode, "PROXY"))
    {
        server_args_ret->mode = SERVER_MODE_PROXY;
    }
    else
    {
        PRINT_ERROR_INVALID_OPTION_VALUE("%s", mode, "'mode'('m')");
    }

    if (server_args_ret->mode == SERVER_MODE_PROXY)
    {
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
            server_args_ret->listen_port = listen_port;
        }

        if (forward_ip == NULL)
        {
            PRINT_ERROR_REQUIRED_OPTION_NOT_PROVIDED("'fwd-ip'");
        }
        // IP format is not checked here
        else if (strlen(forward_ip) >= IP_STR_LENGTH)
        {
            PRINT_ERROR_INVALID_OPTION_VALUE("%s", forward_ip, "'fwd-ip'");
        }

        strcpy(server_args_ret->forward_ip, forward_ip);

        if (forward_port == -1)
        {
            PRINT_ERROR_REQUIRED_OPTION_NOT_PROVIDED("'fwd-port'");
        }
        else if (forward_port < 0 || forward_port > 65535)
        {
            PRINT_ERROR_INVALID_OPTION_VALUE("%d", forward_port, "'fwd-port'");
        }

        server_args_ret->forward_port = forward_port;
    }
    else if (server_args_ret->mode == SERVER_MODE_KGC)
    {
        server_args_ret->listen_port = kKgcListenPort;
    }
}