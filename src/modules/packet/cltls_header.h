#ifndef CLTLS_HEADER_H_
#define CLTLS_HEADER_H_

#include <stdint.h>

typedef struct {
    uint8_t type_af;
    uint8_t protocol;

} ClientHelloHeader;

#endif