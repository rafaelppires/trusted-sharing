#ifndef SGX_CRYPTO_H
#define SGX_CRYPTO_H

#include <stdio.h>

#if defined (__cplusplus)
extern "C" {
#endif

#ifdef ENABLE_SGX
extern int printf(const char *fmt, ...);
#endif

unsigned char* gen_random_bytestream(size_t n);
void sgx_random(size_t n, unsigned char *buff);

static inline void print_hex(unsigned char *h, int l)
{
    for (int i=0; i<l; i++)
        printf("%02X", h[i]);
    printf("\n");
}

/* ------- AES OPERATIONS ---------- */
void sgx_aes128_encrypt(const unsigned char* plaintext,
    int plaintext_size,
    unsigned char* key, unsigned char* iv,
    unsigned char* ciphertext);

void sgx_aes128_decrypt(const unsigned char* ciphertext,
    int ciphertext_len,
    unsigned char* key, unsigned char* iv,
    unsigned char* plaintext);

/* ------- SHA OPERATIONS ---------- */
unsigned char* sgx_sha256(const unsigned char *d, 
    size_t n, 
    unsigned char *md);

/* ------- RSA OPERATIONS ---------- */
int rsa_encryption(unsigned char* plaintext, int plaintext_length,
    char* key, int key_length,
    unsigned char* ciphertext);
    
int rsa_decryption(unsigned char* ciphertext, int ciphertext_length,
    char* key, int key_length,
    unsigned char* plaintext);

/* ------- ECC OPERATIONS ---------- */
int ecc_encryption(unsigned char* plaintext, int plaintext_length,
    char* key, int key_length,
    unsigned char* ciphertext);
    
int ecc_decryption(unsigned char* ciphertext, int ciphertext_length,
    char* key, int key_length,
    unsigned char* plaintext);


#if defined (__cplusplus)
}
#endif


// SGX_CRYPTO_H
#endif
