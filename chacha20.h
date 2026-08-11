#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <string.h>

typedef struct{
    uint32_t key[8];
    uint32_t nonce[3];
    uint32_t counter;
    uint32_t state[16];
}chacha20;
#endif

void QuaterRound(uint32_t *s, unsigned int a, unsigned int b, unsigned int c, unsigned int d);
void InitState(chacha20 *cha);
void inner_block(chacha20 *cha);
uint8_t* serialize(chacha20 *cha, uint8_t out[64]);
uint8_t* chacha20_block(chacha20 *cha, uint8_t out[64]);
void encrypt(chacha20 *cha, uint8_t *plaintext, uint8_t *ciphertext, unsigned int len);