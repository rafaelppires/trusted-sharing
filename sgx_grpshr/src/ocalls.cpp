#include <stdio.h>

extern "C" {
void ocall_print( const char *str ) {
    printf("\033[32;1m|\033[0m %s",str);
}
}

