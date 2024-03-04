#ifndef LOG_H_
#define LOG_H_

#include <stdio.h>
#include <stdarg.h>

#include <common/def.h>

#define STYLE_NRM "\x1B[0m"
#define STYLE_RED "\x1B[31m"
#define STYLE_GRN "\x1B[32m"
#define STYLE_YEL "\x1B[33m"
#define STYLE_BLU "\x1B[34m"
#define STYLE_MAG "\x1B[35m"
#define STYLE_CYN "\x1B[36m"
#define STYLE_WHT "\x1B[37m"
#define STYLE_BOLD "\x1B[1m"

void Log(const LogType log_type,
         const char *format,
         ...);

void LogError(const char *format,
              ...);

void LogWarn(const char *format,
             ...);

void LogInfo(const char *format,
             ...);

void LogSuccess(const char *format,
                ...);

void LogTiming(const char *format,
               ...);

#endif