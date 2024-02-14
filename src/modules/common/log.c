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
            fputs(STYLE_RED, stderr);
            vfprintf(stderr, format, args);
            fputs(STYLE_NRM, stderr);
            break;
        case LOG_TYPE_WARN:
            fputs(STYLE_YEL, stdout);
            vfprintf(stdout, format, args);
            fputs(STYLE_NRM, stdout);
            break;
        default:
            vfprintf(stdout, format, args);
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