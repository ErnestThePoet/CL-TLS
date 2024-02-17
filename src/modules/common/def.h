#ifndef DEF_H_
#define DEF_H_

#include <string.h>
#include <errno.h>

// More severe the level, greater the value
typedef enum
{
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO
} LogLevel;

typedef enum
{
    LOG_TYPE_ERROR,
    LOG_TYPE_WARN,
    LOG_TYPE_INFO
} LogType;

LogLevel kLogLevel = LOG_LEVEL_WARN;

#define MAX_PATH_LENGTH 80
#define STR_ERRNO strerror(errno)

#endif