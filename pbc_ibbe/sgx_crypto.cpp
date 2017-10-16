#include "sgx_crypto.h"
#ifndef ENABLE_SGX // sgx {
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#else // } else {
#include <libc_mock/libc_proxy.h>
#include <sgx_cryptoall.h>
#endif // }
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

void sgx_aes128_encrypt(
    const uint8_t* plaintext,
    int plaintext_size,
    uint8_t* key, uint8_t* iv,
    uint8_t* ciphertext)
{
#ifndef ENABLE_SGX
    int len;
    int ciphertext_len;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
//    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_size);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
#else
    encrypt_aes128( plaintext, ciphertext, plaintext_size, key, iv );
#endif
}

void sgx_aes128_decrypt(
    const uint8_t* ciphertext,
    int ciphertext_len,
    uint8_t* key, uint8_t* iv,
    uint8_t* plaintext)
{
#ifndef ENABLE_SGX
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
//    EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, (plaintext) + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
#else
    decrypt_aes128( ciphertext, plaintext, ciphertext_len, key, iv );
#endif
}

int rsa_encryption(
    uint8_t* plaintext, int plaintext_length,
    char* key, int key_length,
    uint8_t* ciphertext)
{
#ifndef ENABLE_SGX
    BIO *bio_buffer = NULL;
    RSA *rsa = NULL;

    bio_buffer = BIO_new_mem_buf((void*)key, key_length);
    PEM_read_bio_RSA_PUBKEY(bio_buffer, &rsa, 0, NULL);
    
    int ciphertext_size = RSA_public_encrypt(
        plaintext_length,
        plaintext,
        ciphertext,
        rsa,
        RSA_PKCS1_PADDING);
                
    return ciphertext_size;
#else
    printf("rsa_encryption\n"); 
#endif
}

int rsa_decryption(
    uint8_t* ciphertext, int ciphertext_length,
    char* key, int key_length,
    uint8_t* plaintext)
{
#ifndef ENABLE_SGX
    BIO *bio_buffer = NULL;
    RSA *rsa = NULL;

    bio_buffer = BIO_new_mem_buf((void*)key, key_length);
    PEM_read_bio_RSAPrivateKey(bio_buffer, &rsa, 0, NULL);
    
    int plaintext_length = RSA_private_decrypt(
        ciphertext_length,
        ciphertext,
        plaintext,
        rsa,
        RSA_PKCS1_PADDING);
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

