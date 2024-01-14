#ifndef DEF_H_
#define DEF_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define SUCCESS 0
#define FAILURE 1

#define EXIT_FAILURE exit(FAILURE)

#define PRINT_ERROR(F, M)    \
    do                       \
    {                        \
        fprintf(stderr, "%s error: %s\n",F,M); \
    \ 
} while (0)

#define STR_ERRNO strerror(errno)

#endif