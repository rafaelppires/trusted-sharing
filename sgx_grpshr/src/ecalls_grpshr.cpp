#include <pbc.h>
#include <enclave_grpshr_t.h>
#include <libc_mock/file_mock.h>

extern "C" {
int printf(const char *fmt, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    int ret = vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print(buf);
    return ret;
}
}

//====================== ECALLS ================================================
void ecall_handlerequest( int a, int b ) {
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
}

