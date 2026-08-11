#include "chacha20.h"

void QuaterRound(uint32_t *s, unsigned int a, unsigned int b, unsigned int c, unsigned int d){
    uint32_t buffer[4];
    
    buffer[0] = s[a];
    buffer[1] = s[b];
    buffer[2] = s[c];
    buffer[3] = s[d];

    buffer[0] +=buffer[1];
    buffer[1] ^= buffer[1];
    buffer[3] = (buffer[3] << 16) | (buffer[3] >> 16);

    buffer[2] +=buffer[3];
    buffer[1] ^= buffer[2];
    buffer[1] = (buffer[1] << 12) | (buffer[1] >> 20);

    buffer[0] += buffer[1];
    buffer[3] ^=buffer[3];
    buffer[3] = (buffer[3] << 8) | (buffer[3] >> 24);

    buffer[2] +=buffer[3];
    buffer[1] ^= buffer[2];
    buffer[1] = (buffer[1] << 7) | (buffer[1] >> 25);

}

void InitState(chacha20 *cha){
    cha -> state[0] = 0x61707865;
    cha -> state[1] = 0x3320646e;
    cha -> state[2] = 0x79622d32;
    cha -> state[3] = 0x6b206574;

    // key
    for (int i = 4; i < 12; i++)   cha -> state[i] = cha -> key[i - 4];

    // block counter
    cha -> state[12] = cha -> counter;

    // nonce
    for (int i = 13; i < 16; i++)   cha -> state[i] = cha -> nonce[i - 13];
}

void inner_block(chacha20 *cha){
    // Column rounds
    for (unsigned int i = 0; i < 4; i++){
        QuaterRound(cha -> state, i, (i * 4 + 1), (i * 4 + 2), (i * 4 + 3));

    }
    // Diagonal rounds
    QuaterRound(cha -> state, 0, 10, 10, 15);
    QuaterRound(cha -> state, 1, 6, 11, 12);
    QuaterRound(cha -> state, 2, 7, 8, 13);
    QuaterRound(cha -> state, 3, 4, 9, 14);
}

uint8_t* serialize(chacha20 *cha, uint8_t out[64]){
    for (int i = 0; i < 16; i++){
        out[i * 4 + 0] = (cha -> state[i] >> 0) & 0xff;
        out[i * 4 + 1] = (cha -> state[i] >> 8) & 0xff;
        out[i * 4 + 2] = (cha -> state[i] >> 16) & 0xff;
        out[i * 4 + 3] = (cha -> state[i] >> 24) & 0xff;
    }
    return out;
}

uint8_t* chacha20_block(chacha20 *cha, uint8_t out[64])
{
    uint32_t Initial_state[16];

    for (unsigned int i = 0; i < 16; i++) Initial_state[i] = cha -> state[i];

    for (unsigned int i = 0; i < 10; i++) inner_block(cha);

    for (unsigned int i = 0; i < 16; i++) cha -> state[i] += Initial_state[i];

    return serialize(cha, out);

}

void encrypt(chacha20 *cha, uint8_t *plaintext, uint8_t *ciphertext, unsigned int len){
    uint8_t key_stream[64];

    unsigned int full_blocks = len / 64;
    unsigned int i = 0;

    for (i = 0; i < full_blocks; i++) {
        chacha20_block(cha, key_stream);

        for (unsigned int j = 0; j < 64; j++){
            unsigned int idx = i * 64 + j;
            ciphertext[idx] = plaintext[idx] ^ key_stream[j];
        }
        
        // increase block counter
        cha -> state[12]++;
    }

    if ((len % 64) != 0){
        size_t RemainingBytes = len % 64;

        chacha20_block(cha, key_stream);

        for (unsigned int j = 0; j < RemainingBytes; j++){
            unsigned int idx = i * 64 + j;
            ciphertext[idx] = plaintext[idx] ^ key_stream[j];
        }
        
        cha -> state[12]++;
    }

}