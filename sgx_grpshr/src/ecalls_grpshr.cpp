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

typedef unsigned char uchar;
using Crypto::printable;
//====================== ECALLS ================================================
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
    const char *plain = "very secret stuff\n";
    size_t sz         = strlen(plain)+1;
    uchar *cipher     = (uchar*)malloc(sz),
          *recovered  = (uchar*)malloc(sz);
    uchar *key = gen_random_bytestream(16),
          *iv  = gen_random_bytestream(16);

    printf("Random key and iv\n");
    printf("key: %s\n",printable(std::string((char*)key,16)).c_str());
    printf("iv:  %s\n",printable(std::string((char*)iv,16)).c_str());
    sgx_aes128_encrypt( (const uchar*)plain, sz, key, iv, cipher );
    printf("%s\n", printable( std::string((char*)cipher,sz) ).c_str() );
    sgx_aes128_decrypt( (const uchar*)cipher, sz, key, iv, recovered );
    printf("%s\n", printable( std::string((char*)recovered,sz).c_str() ).c_str());

    printf("Fixed key and iv\n");
    memset(key,0,16); key[0] = '1'; key[12] = 'j';
    memset(iv,0,16);  iv[0] = '9';  iv[15] = '*';
    printf("key: %s\n",printable(std::string((char*)key,16)).c_str());
    printf("iv:  %s\n",printable(std::string((char*)iv,16)).c_str());
    sgx_aes128_encrypt( (const uchar*)plain, sz, key, iv, cipher );
    printf("%s\n", Crypto::printable( std::string((char*)cipher,sz) ).c_str() );
    sgx_aes128_decrypt( (const uchar*)cipher, sz, key, iv, recovered );
    printf("%s\n", Crypto::printable( std::string((char*)recovered,sz).c_str() ).c_str());

    free(cipher);
    free(recovered);
    free(key);
    free(iv);
}

