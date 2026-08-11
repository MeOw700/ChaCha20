#include <stdio.h>
#include <string.h>
#include "chacha20.h"

int hex_to_bytes(const char *hex_str, uint8_t *bytes, size_t max_len) {
    const char *pos = hex_str;
    size_t count = 0;

    while (*pos && count < max_len) {
        int offset = 0;
        if (sscanf(pos, "%hhx%n", &bytes[count], &offset) == 1) {
            pos += offset;
            count++;
        } else {
            break;
        }
    }
    return count;
}

int main(){
    // Plaintext
    const char *plaintext = "27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61 6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f 76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64 20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77"
                            "61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77 65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65 73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20 72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e";
    uint8_t raw_plaintext[500];
    size_t len = hex_to_bytes(plaintext, raw_plaintext, sizeof(raw_plaintext));
    uint8_t ciphertext[len];

    chacha20 cha;
    memset(&cha, 0, sizeof(chacha20));
    
    // Key
    const char *key_hex = "1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0";
    uint8_t raw_key[32];
    hex_to_bytes(key_hex, raw_key, sizeof(raw_key));
    memcpy(cha.key, raw_key, sizeof(raw_key));

    // Nonce
    const char *nonce_hex = "00 00 00 00 00 00 00 00 00 00 00 02";
    uint8_t raw_nonce[12];
    hex_to_bytes(nonce_hex, raw_nonce, sizeof(raw_nonce));
    memcpy(cha.nonce, raw_nonce, sizeof(raw_nonce));

    //counter 
    cha.counter = 42;

    // Encrypt
    encrypt(&cha, (uint8_t *)plaintext, ciphertext, len);

    // Print result
    printf("Plaintext : %s\n", plaintext);
    printf("Encrypted :");
    for (unsigned int i = 0; i < len; i++){
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");

    return 0;
}