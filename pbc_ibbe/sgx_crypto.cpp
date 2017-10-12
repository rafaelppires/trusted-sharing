#include "sgx_crypto.h"
#ifndef ENABLE_SGX
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#else
#include <libc_mock/libc_proxy.h>
#endif
#include <stdlib.h>
#include <unistd.h>

unsigned char* gen_random_bytestream(size_t n)
{
    unsigned char* stream = (unsigned char*) malloc(n + 1);
    sgx_random(n,stream);
    stream[n] = 0;
    return stream;
}

void sgx_random(size_t n, unsigned char *buff) {
    size_t i;
    for (i = 0; i < n; i++)
    {
        buff[i] = (unsigned char) (rand() % 255 + 1);
    }
}

void sgx_aes128_encrypt(
    const unsigned char* plaintext,
    int plaintext_size,
    unsigned char* key, unsigned char* iv,
    unsigned char* ciphertext)
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
    printf("sgx_aes_encrypt\n"); 
#endif
}

void sgx_aes128_decrypt(
    const unsigned char* ciphertext,
    int ciphertext_len,
    unsigned char* key, unsigned char* iv,
    unsigned char* plaintext)
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
    printf("sgx_aes_decrypt\n"); 
#endif
}

int rsa_encryption(
    unsigned char* plaintext, int plaintext_length,
    char* key, int key_length,
    unsigned char* ciphertext)
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
    unsigned char* ciphertext, int ciphertext_length,
    char* key, int key_length,
    unsigned char* plaintext)
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

unsigned char* sgx_sha256(const unsigned char *d, 
    size_t n, 
    unsigned char *md)
{
#ifndef ENABLE_SGX
    return SHA256(d, n, md);
#else
    printf("sgx_sha256\n"); 
    return 0;
#endif
}

int ecc_encryption(unsigned char* plaintext, int plaintext_length,
    char* key, int key_length,
    unsigned char* ciphertext)
{
}

int ecc_decryption(unsigned char* ciphertext, int ciphertext_length,
    char* key, int key_length,
    unsigned char* plaintext)
{
}
