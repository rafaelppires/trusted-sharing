#include "tests.h"
//#include "admin_api.h"
//#include "hybrid_api.h"
#include <stdio.h>
//#include "microbench.h"

void sp_ibbe_functional_tests()
{
    /*
    char* s[2] = {"main\0", "a.param\0"};    
    ftest_one_user(2, s);
	ftest_create_group_decrypt_all(2, s, 30, 10);
    ftest_add_users_decrypt_all(2, s, 20, 10);
    ftest_remove_decrypt_all(2, s, 20, 9);
*/
}

void api_tests()
{
    admin_api(1000, 1000);
}

void all_functional_tests()
{
    sp_ibbe_functional_tests();
    //api_tests();
}

int main(int argc, char **argv)
{
    char* s[2] = {"main\0", "a.param\0"};    
    test_border_sgx_create_group(2, s);
    //test_admin_replay();
}
