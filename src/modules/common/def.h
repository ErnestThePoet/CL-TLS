#ifndef DEF_H_
#define DEF_H_

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

typedef struct
{
    uint8_t cipher_suite;
} CipherSuite;
#define P
#define T CipherSuite
#include <set.h>

int CipherSuiteCmp(CipherSuite *a, CipherSuite *b);

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
    LOG_TYPE_SUCCESS,
    LOG_TYPE_INFO
} LogType;

extern LogLevel kLogLevel;

#define ENTITY_IDENTITY_LENGTH 32
#define ENTITY_IDENTITY_HEX_LENGTH (ENTITY_IDENTITY_LENGTH * 2)
#define ENTITY_IDENTITY_HEX_STR_LENGTH (ENTITY_IDENTITY_HEX_LENGTH + 1)
#define IP_STR_LENGTH INET_ADDRSTRLEN
#define MAX_PATH_LENGTH 80
#define MIN_SOCKET_BLOCK_SIZE 256

#define INITIAL_SOCKET_BUFFER_CAPACITY 256
#define INITIAL_TRAFFIC_BUFFER_CAPACITY 512

#define MAX_HASH_LENGTH 32
#define MAX_ENC_KEY_LENGTH 16
#define MAX_NPUB_IV_LENGTH 16
#define MAX_ENC_BLOCK_SIZE 16
#define MAX_ENC_TAG_SIZE 16
#define MAX_ENC_EXTRA_SIZE (MAX_ENC_BLOCK_SIZE + MAX_ENC_TAG_SIZE)

#define STR_ERRNO strerror(errno)

extern uint8_t kKgcIdentity[ENTITY_IDENTITY_LENGTH];

extern uint16_t kKgcListenPort;

#endif