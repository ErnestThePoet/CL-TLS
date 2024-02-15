#include "parse_server_args.h"

void ParseServerArgs(
    const int argc, char *argv[], ServerArgs *server_args_ret)
{
    const char *mode = NULL;
    int listen_port = -1;
    const char *forward_ip = NULL;
    int forward_port = -1;
    const char *log_level = NULL;
    const char *preferred_cipher_suite = NULL;

    const char *usages[] = {
        "cltls_server [options]",
        NULL};

    struct argparse_option options[] =
        {
            OPT_HELP(),
            OPT_GROUP("Mandatory options"),
            OPT_STRING('m', "mode", &mode, "server mode(KGC|PROXY)", NULL, 0, 0),
            OPT_INTEGER('p', "port", &listen_port, "listen port", NULL, 0, 0),
            OPT_GROUP("Options required in PROXY mode"),
            OPT_STRING('\0', "fwd-ip", &forward_ip, "proxy forward ip", NULL, 0, 0),
            OPT_INTEGER('\0', "fwd-port", &forward_port, "proxy forward port", NULL, 0, 0),
            OPT_GROUP("Optional options"),
            OPT_STRING('l', "log", &log_level, "log level(ERROR|WARN|INFO), defaults to 'WARN'", NULL, 0, 0),
            OPT_STRING('\0', "cipher", &preferred_cipher_suite, "preferred cipher suite(ASCON128A_ASCONHASHA|ASCON128A_SHA256|AES128GCM_ASCONHASHA|AES128GCM_SHA256), defaults to 'ASCON128A_ASCONHASHA'", NULL, 0, 0),
            OPT_END(),
        };

    struct argparse arg_parse;
    argparse_init(&arg_parse, options, usages, 0);
    argparse_describe(&arg_parse,
                      "\nThe server implementation of CL-TLS which can run as a KGC or proxy.",
                      NULL);
    argparse_parse(&arg_parse, argc, (const char **)argv);

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

    if (listen_port == -1)
    {
        PRINT_ERROR_REQUIRED_OPTION_NOT_PROVIDED("'port'('p')");
    }
    else if (listen_port < 0 || listen_port > 65535)
    {
        PRINT_ERROR_INVALID_OPTION_VALUE("%d", listen_port, "'port'('p')");
    }

    if (server_args_ret->mode == SERVER_MODE_PROXY)
    {
        if (forward_ip == NULL)
        {
            PRINT_ERROR_REQUIRED_OPTION_NOT_PROVIDED("'fwd-ip'");
        }
        // IP format is not checked here
        else if (strlen(forward_ip) >= 50)
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

    if (log_level == NULL || !strcmp(log_level, "WARN"))
    {
        kLogLevel = LOG_LEVEL_WARN;
    }
    else if (!strcmp(log_level, "ERROR"))
    {
        kLogLevel = LOG_LEVEL_ERROR;
    }
    else if (!strcmp(log_level, "INFO"))
    {
        kLogLevel = LOG_LEVEL_INFO;
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
    else if (!strcmp(preferred_cipher_suite, "ASCON128A_ASCONHASHA"))
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
}