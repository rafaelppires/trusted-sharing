/*

Security level	r	        q^k	                k with ρ ≈ 1	k with ρ ≈ 2
80 bits	        160 bits	960–1280 bits	    6–8	            2–4
128 bits	    256 bits	3000–5000 bits	    12–20	        6–10
256 bits	    512 bits	14000–18000 bits	28–36	        14–18

Source: https://www.ncbi.nlm.nih.gov/pmc/articles/PMC4730686/
---

Security levels (in bits)		80		112		128
Bit-length of r (prime order)	160		224		256
Bit length of q	(field size)	512		1024	1536

----

Equivalence to RSA:
80		1024
112		2048
128		3072
*/

#include <stdio.h>

#ifdef ENABLE_SGX
#include <enclave_grpshr_u.h>
#include <sgx_initenclave.h>
#include <unistd.h>
#include <libgen.h>
sgx_enclave_id_t global_eid = 0;    /* global enclave id */
#else
#include <pbc.h>
extern void ecall_handlerequest( int a, int b );
#endif

int main( int argc, char **argv ) {
#ifdef ENABLE_SGX
    /* Changing dir to where the executable is.*/
    char *ptr = realpath( dirname(argv[0]),NULL );

    if( ptr == NULL ){ perror("Error:"); abort(); }
    if( chdir(ptr) != 0) abort();

    /* Initialize the enclave */
    if(initialize_enclave( global_eid,
                           "grpshr.signed.so","enclave.grpshrpbc.token") < 0) {
        return -2;
    }
    free(ptr);

    sgx_status_t ret1, ret2;
    ret1 = ecall_handlerequest(global_eid, 224,1024);
//    ret2 = ecall_handlerequest(global_eid, 256,1536);
#else
    FILE *f = fopen("/dev/urandom","r");
    unsigned int seed;
    fread(&seed,1,sizeof(seed),f);
    srand(seed);
    fclose(f);
    ecall_handlerequest(224,1024);
#if 0
	pbc_param_t par;
	pbc_param_init_a_gen(par, 224, 1024);
	FILE* pf = fopen ("a_224_1024.param", "w");
	pbc_param_out_str(pf, par);
	fclose(pf);

	pbc_param_t par1;
	pbc_param_init_a_gen(par1, 256, 1536);
	FILE* pf1;
	pf1 = fopen ("a_256_1536.txt", "w") ;
	pbc_param_out_str(pf1, par1);
	fclose(pf1);
#endif
#endif
}

