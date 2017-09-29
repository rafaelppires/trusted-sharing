#include <pbc.h>
#include <enclave_curves_t.h>

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
    printf("hallo\n");
    pbc_param_t par;
    pbc_param_init_a_gen(par, 224, 1024);
}

