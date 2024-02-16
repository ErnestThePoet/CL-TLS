#ifndef ASCON128A_WRAPPER_H_
#define ASCON128A_WRAPPER_H_

#include <stdint.h>

#include <ascon/ascon_aead.h>

#include "crypto_wrapper.h"

// extra1 is used as npub
int Ascon128AEncrypt(const uint8_t *m, size_t mlen,
                     uint8_t *c, size_t *clen,
                     const uint8_t *ad, size_t adlen,
                     const uint8_t *k,
                     void *extra1,
                     void *extra2);

// extra1 is used as npub
int Ascon128ADecrypt(const uint8_t *c, size_t clen,
                     uint8_t *m, size_t *mlen,
                     const uint8_t *ad, size_t adlen,
                     const uint8_t *k,
                     void *extra1,
                     void *extra2);

static AeadScheme kAeadSchemeAscon128A_ = {
    .Encrypt = Ascon128AEncrypt,
    .Decrypt = Ascon128ADecrypt,
    .key_size = 16};

AeadScheme *kAeadSchemeAscon128A = &kAeadSchemeAscon128A_;

#endif