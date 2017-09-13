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

#include <pbc.h>

int main() {
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
	fclose(pf1, par1);
}
