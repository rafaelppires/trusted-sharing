#ifndef HYBRID_SGX_H
#define HYBRID_SGX_H

#include <vector>
#include <string>
#include "sgx_ibbe.h"

// Hybrid ecnryption schemes, used for comparison benchmarks.

void hybrid_sgx_create_group(std::vector<std::string> members, std::vector<std::string>& encryptedKeys, bool useRsa);
void hybrid_sgx_add_user(std::vector<std::string>& members, std::vector<std::string>& encryptedKeys, std::string user_id, bool useRsa);
void hybrid_sgx_remove_user(std::vector<std::string>& members, std::vector<std::string>& encryptedKeys, std::string user_id, bool useRsa);

// HYBRID_SGX_H
#endif