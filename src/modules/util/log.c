#include "log.h"

static void VLog(const LogType log_type,
                 const char *format,
                 va_list args)
{
    if ((int)kLogLevel <= (int)log_type)
    {
        switch (log_type)
        {
        case LOG_TYPE_ERROR:
            fputs(STYLE_RED STYLE_BOLD "Error: " STYLE_NRM STYLE_RED, stderr);
            vfprintf(stderr, format, args);
            fputs(STYLE_NRM, stderr);
            fputc('\n', stderr);
            break;
        case LOG_TYPE_WARN:
            fputs(STYLE_YEL STYLE_BOLD "Warn: " STYLE_NRM STYLE_YEL, stdout);
            vfprintf(stdout, format, args);
            fputs(STYLE_NRM, stdout);
            fputc('\n', stdout);
            break;
        case LOG_TYPE_SUCCESS:
            fputs(STYLE_GRN STYLE_BOLD "Success: " STYLE_NRM STYLE_GRN, stdout);
            vfprintf(stdout, format, args);
            fputs(STYLE_NRM, stdout);
            fputc('\n', stdout);
            break;
        case LOG_TYPE_INFO:
            fputs(STYLE_BOLD "Info: " STYLE_NRM, stdout);
            vfprintf(stdout, format, args);
            fputc('\n', stdout);
            break;
        default:
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

void LogSuccess(const char *format,
                ...)
{
    va_list args;
    va_start(args, format);
    VLog(LOG_TYPE_SUCCESS, format, args);
    va_end(args);
}

void LogTiming(const char *format,
               ...)
{
    va_list args;
    va_start(args, format);
    fputs(STYLE_BLU STYLE_BOLD "<Timing> " STYLE_NRM STYLE_BLU, stdout);
    vfprintf(stdout, format, args);
    fputs(STYLE_NRM, stdout);
    fputc('\n', stdout);
    va_end(args);
}