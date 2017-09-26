#include <pbc.h>
#include <enclave_curves_t.h>

extern "C" {
void printf(const char *fmt, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print(buf);
}
}

//====================== ECALLS ================================================
void ecall_handlerequest( int a, int b ) {
    ocall_print("hallo");
    pbc_param_t par;
    pbc_param_init_a_gen(par, 224, 1024);
}

