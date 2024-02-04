#ifndef DEF_H_
#define DEF_H_

#include <string.h>
#include <errno.h>

#define SUCCESS 0
#define FAILURE 1

typedef enum
{
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO
} LogLevel;

#define STR_ERRNO strerror(errno)

#endif