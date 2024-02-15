#include "log.h"

static void VLog(const LogType log_type,
                 const LogLevel log_level,
                 const char *format,
                 va_list args)
{
    if (log_level >= log_type)
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
         const LogLevel log_level,
         const char *format,
         ...)
{
    va_list args;
    va_start(args, format);
    VLog(log_type, log_level, format, args);
    va_end(args);
}

void LogError(const LogLevel log_level,
              const char *format,
              ...)
{
    va_list args;
    va_start(args, format);
    VLog(LOG_TYPE_ERROR, log_level, format, args);
    va_end(args);
}

void LogWarn(const LogLevel log_level,
             const char *format,
             ...)
{
    va_list args;
    va_start(args, format);
    VLog(LOG_TYPE_WARN, log_level, format, args);
    va_end(args);
}

void LogInfo(const LogLevel log_level,
             const char *format,
             ...)
{
    va_list args;
    va_start(args, format);
    VLog(LOG_TYPE_INFO, log_level, format, args);
    va_end(args);
}