#ifndef SGX_CRYPTO_H
#define SGX_CRYPTO_H

#include <stdio.h>
#include <stdint.h>

#if defined (__cplusplus)
extern "C" {
#endif

#ifdef ENABLE_SGX
extern int printf(const char *fmt, ...);
#endif

static inline void print_hex(uint8_t *h, int l)
{
    for (int i=0; i<l; i++)
        printf("%02X", h[i]);
    printf("\n");
}

/* ------- RANDOM -------- */
uint8_t* gen_random_bytestream(size_t n);
void sgx_random(size_t n, uint8_t *buff);

/* ------- AES OPERATIONS ---------- */
void sgx_aes128_encrypt(const uint8_t* plaintext,
    int plaintext_size,
    uint8_t* key, uint8_t* iv,
    uint8_t* ciphertext);

void sgx_aes128_decrypt(const uint8_t* ciphertext,
    int ciphertext_len,
    uint8_t* key, uint8_t* iv,
    uint8_t* plaintext);

/* ------- SHA OPERATIONS ---------- */
uint8_t* sgx_sha256(const uint8_t *d, 
    size_t n, 
    uint8_t *md);

/* ------- RSA OPERATIONS ---------- */
int rsa_encryption(uint8_t* plaintext, int plaintext_length,
    char* key, int key_length,
    uint8_t* ciphertext);
    
int rsa_decryption(uint8_t* ciphertext, int ciphertext_length,
    char* key, int key_length,
    uint8_t* plaintext);

#if defined (__cplusplus)
}
#endif


// SGX_CRYPTO_H
#endif
