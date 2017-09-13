#ifndef TESTS_H
#define TESTS_H

#include "admin_api.h"

/*
 *   FUNCTIONAL TESTS
 */
void ftest_one_user(int argc, char** argv);
void ftest_create_group_decrypt_all(int argc, char** argv, int g_size, int p_size);
void ftest_add_users_decrypt_all(int argc, char** argv, int g_size, int p_size);
void ftest_remove_decrypt_all(int argc, char** argv, int g_size, int p_size);
void ftest_add_remove_decrypt_all(int argc, char** argv, int g_size, int p_size);

void admin_api(int g_size, int p_size);

/*
 *   PERFORMANCE TESTS
 */

// MICROBENCHMARKS
void micro_create_group(AdminApi* adminApi);
void micro_add_user(AdminApi* adminApi);
void micro_remove_user(AdminApi* adminApi);
void micro_decrypt_key(AdminApi* adminApi, UserApi* userApi);

// TESTS_H
#endif
