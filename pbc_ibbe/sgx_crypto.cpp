#include "sgx_crypto.h"
#ifndef ENABLE_SGX // sgx {
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#else             // } else {
#include <libc_mock/libc_proxy.h>
#endif            // }
#include <sgx_cryptoall.h>
#include <stdlib.h>
#include <unistd.h>
#include <cstdlib>

uint8_t* gen_random_bytestream(size_t n)
{
    uint8_t* stream = (uint8_t*) malloc(n + 1);
    sgx_random(n,stream);
    stream[n] = 0;
    return stream;
}

void sgx_random(size_t n, uint8_t *buff) {
    size_t i;
    for (i = 0; i < n; i++)
    {
        buff[i] = (uint8_t) (rand() % 255 + 1);
    }
}

void sgx_aes256_encrypt(
    const uint8_t* plaintext,
    int plaintext_size,
    uint8_t* key, uint8_t* iv,
    uint8_t* ciphertext)
{
    encrypt_aes( AES256, plaintext, ciphertext, plaintext_size, key, iv );
}

void sgx_aes256_decrypt(
    const uint8_t* ciphertext,
    int ciphertext_len,
    uint8_t* key, uint8_t* iv,
    uint8_t* plaintext)
{
    decrypt_aes( AES256, ciphertext, plaintext, ciphertext_len, key, iv );
}

int rsa_encryption( const uint8_t* plaintext, size_t plain_len,
                    char* key, uint8_t* ciphertext, size_t cipher_len )
{
#ifndef ENABLE_SGX
    BIO *bio_buffer = NULL;
    RSA *rsa = NULL;

    bio_buffer = BIO_new_mem_buf((void*)key, -1);
    PEM_read_bio_RSA_PUBKEY(bio_buffer, &rsa, 0, NULL);
    size_t rsa_min = RSA_size( rsa );
    if( cipher_len < rsa_min ) {
        return -rsa_min;
    }

    int ciphertext_size = RSA_public_encrypt( plain_len, plaintext,
                                              ciphertext,
                                              rsa, RSA_PKCS1_PADDING );
    return ciphertext_size;
#else
    encrypt_rsa(plaintext,plain_len,key,ciphertext,cipher_len);
    return 0;
#endif
}

int rsa_decryption(const uint8_t* ciphertext, size_t cipher_len,
                   char* key, uint8_t* plaintext, size_t plain_len)
{
#ifndef ENABLE_SGX
    BIO *bio_buffer = NULL;
    RSA *rsa = NULL;

    bio_buffer = BIO_new_mem_buf((void*)key, -1);
    PEM_read_bio_RSAPrivateKey(bio_buffer, &rsa, 0, NULL);
    size_t rsa_min = RSA_size( rsa );
    if( plain_len < rsa_min ) {
        return -rsa_min;
    }
    
    int plaintext_length = RSA_private_decrypt( cipher_len, ciphertext,
                                                plaintext,
                                                rsa, RSA_PKCS1_PADDING);
    return plaintext_length;
#else
    printf("rsa_decryption\n"); 
    return 0;
#endif
}

uint8_t* sgx_sha256(const uint8_t *d, 
    size_t n, 
    uint8_t *md)
{
#ifndef ENABLE_SGX
    return SHA256(d, n, md);
#else
    return sgx_sha256_msg(d,n,(uint8_t(*)[32])md) == SGX_SUCCESS ? md : NULL;
#endif
}

int ecc_encryption(uint8_t* plaintext, int plaintext_length,
    char* key, int key_length,
    uint8_t* ciphertext)
{
}

int ecc_decryption(uint8_t* ciphertext, int ciphertext_length,
    char* key, int key_length,
    uint8_t* plaintext)
{
}

