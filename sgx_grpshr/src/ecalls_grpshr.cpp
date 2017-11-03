#include <pbc.h>
#include <string.h>
#include <sgx_crypto.h>
#include <sgx_cryptoall.h>

#ifdef ENABLE_SGX // sgx {
#include <enclave_grpshr_t.h>
#include <libc_mock/file_mock.h>

#if defined(__cplusplus) // cxx {
extern "C" {
    int printf(const char *fmt, ...);
}
#endif // } cxx
int printf(const char *fmt, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    int ret = vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print(buf);
    return ret;
}
#endif // } sgx

using Crypto::printable;
//====================== ECALLS ================================================

char rsaPrivKey[]="-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
"vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
"Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
"yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
"WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
"gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
"omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
"N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
"X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
"gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
"vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
"1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
"m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
"uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
"JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
"4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
"WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
"nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
"PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
"SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
"I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
"ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
"yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
"w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
"uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
"-----END RSA PRIVATE KEY-----\n";

char rsaPubKey[]="-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
"wQIDAQAB\n"\
"-----END PUBLIC KEY-----\n";

void ecall_handlerequest( int a, int b ) {
/*
    pbc_param_t par;
    pbc_param_init_a_gen(par, a, b);

    char buf[1024];
    snprintf(buf,sizeof(buf),"a_%d_%d.txt",a,b);
    fmock_allow_writable( buf );
    FILE *pf = fopen(buf,"w");
    pbc_param_out_str(pf, par);
    fmock_flush(buf,sizeof(buf),pf);
    fclose(pf);

    printf(buf);
*/
    size_t aesbits = 256;

    const char *plain = "very secret stuff\n";
    size_t sz         = strlen(plain)+1;
    uint8_t *cipher     = (uint8_t*)malloc(sz),
          *recovered  = (uint8_t*)malloc(sz),
          *hash       = (uint8_t*)malloc(32);
    uint8_t *key = gen_random_bytestream(aesbits/8),
            *iv  = gen_random_bytestream(aesbits/8);

    printf("-----------------\n"
           "Random key and iv\n");
    printf("key: %s\n",printable(std::string((char*)key,aesbits/8)).c_str());
    printf("iv:  %s\n",printable(std::string((char*)iv,aesbits/8)).c_str());
    sgx_aes256_encrypt( (const uint8_t*)plain, sz, key, iv, cipher );
    printf("%s\n", printable( std::string((char*)cipher,sz) ).c_str() );
    sgx_aes256_decrypt( (const uint8_t*)cipher, sz, key, iv, recovered );
    printf("%s\n", printable( std::string((char*)recovered,sz).c_str() ).c_str());

    printf("-----------------\n"
           "RSA\n");
    const char *group_key = "0123456789ABCDEF0123456789ABCDEF";
    char ciphertext[4098];
    int cipher_length = rsa_encryption((const uint8_t*)group_key, strlen(group_key), rsaPubKey, (uint8_t*)ciphertext, sizeof(ciphertext));
    printf("(%d) => %s\n", cipher_length, Crypto::printable(std::string(ciphertext,cipher_length)).c_str());
    if( cipher_length < 0 ) printf("ERROR: destination buffer too small\n");
    char *plaintext = ciphertext+cipher_length+100;
    int plength = rsa_decryption( (const uint8_t*)ciphertext, cipher_length, rsaPrivKey, (uint8_t*)plaintext, sizeof(ciphertext)-cipher_length-100 );
    if( plength < 0 ) printf("ERROR: destination buffer too small\n");
    printf("[%d] => %s\n", plength, Crypto::printable(std::string(plaintext,plength)).c_str());

    printf( "----------------\n"
            "Fixed key and iv\n");
    memset(key,0,aesbits/8); key[0] = '1'; key[12] = 'j';
    memset(iv,0,aesbits/8);  iv[0] = '9';  iv[15] = '*';
    memset(hash,0,32); sgx_sha256(key,16,hash);
    printf("key: %s\n",printable(std::string((char*)key,aesbits/8)).c_str());
    printf("sha256: %s\n",printable(std::string((char*)hash,32)).c_str());
    printf("iv:  %s\n",printable(std::string((char*)iv,aesbits/8)).c_str());
    sgx_aes256_encrypt( (const uint8_t*)plain, sz, key, iv, cipher );
    printf("%s\n", Crypto::printable( std::string((char*)cipher,sz) ).c_str() );
    sgx_aes256_decrypt( (const uint8_t*)cipher, sz, key, iv, recovered );
    printf("%s\n", Crypto::printable( std::string((char*)recovered,sz).c_str() ).c_str());

    free(hash);
    free(cipher);
    free(recovered);
    free(key);
    free(iv);
}

