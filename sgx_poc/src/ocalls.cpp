#include <stdio.h>

extern "C" {
void ocall_print( const char *str ) {
    printf("[%s]\n",str);
}
}

