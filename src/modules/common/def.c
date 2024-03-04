#include "def.h"

int CipherSuiteCmp(CipherSuite *a, CipherSuite *b)
{
    return a->cipher_suite == b->cipher_suite
               ? 0
               : (a->cipher_suite > b->cipher_suite ? 1 : -1);
}

LogLevel kLogLevel = LOG_LEVEL_INFO;

uint8_t kKgcIdentity[ENTITY_IDENTITY_LENGTH] = {
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
    0xEC,
};

uint16_t kKgcListenPort = 27600;