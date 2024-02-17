#include "log.h"

static void VLog(const LogType log_type,
                 const char *format,
                 va_list args)
{
    if (kLogLevel >= log_type)
    {
        switch (log_type)
        {
        case LOG_TYPE_ERROR:
            fputs(stderr, STYLE_RED STYLE_BOLD "Error: " STYLE_NRM STYLE_RED);
            vfprintf(stderr, format, args);
            fputc('\n', stderr);
            fputs(STYLE_NRM, stderr);
            break;
        case LOG_TYPE_WARN:
            fputs(stderr, STYLE_YEL STYLE_BOLD "Warn: " STYLE_NRM STYLE_YEL);
            vfprintf(stdout, format, args);
            fputc('\n', stdout);
            fputs(STYLE_NRM, stdout);
            break;
        default:
            fputs(stderr, STYLE_BOLD "Info: " STYLE_NRM);
            vfprintf(stdout, format, args);
            fputc('\n', stdout);
            break;
        }
    }
}

void Log(const LogType log_type,
         const char *format,
         ...)
{
    va_list args;
    va_start(args, format);
    VLog(log_type, format, args);
    va_end(args);
}

void LogError(const char *format,
              ...)
{
    va_list args;
    va_start(args, format);
    VLog(LOG_TYPE_ERROR, format, args);
    va_end(args);
}

void LogWarn(const char *format,
             ...)
{
    va_list args;
    va_start(args, format);
    VLog(LOG_TYPE_WARN, format, args);
    va_end(args);
}

void LogInfo(const char *format,
             ...)
{
    va_list args;
    va_start(args, format);
    VLog(LOG_TYPE_INFO, format, args);
    va_end(args);
}