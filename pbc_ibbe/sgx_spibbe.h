#ifndef SP_IBBE_H
#define SP_IBBE_H

#include "sgx_ibbe.h"

#include <string>
#include <vector>

class Configuration
{
    public:
        static int UsersPerPartition;
        static std::string CurveFile;
        static const int CipherElemSize = 128; 
};

typedef struct {
    EncryptedGroupKey encGroupKey;
    Ciphertext ciphertext;
    std::vector<std::string> members;
} SpibbePartition;

/* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */ 
/* -------- SGX BORDER METHODS -------- */ 
/* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */ 
#if defined(ENCLAVED) || ! defined(ENABLE_SGX)
extern "C" {

int ecall_create_group(const char* in_buffer, size_t in_bufer_size, char* p_out_buffer, size_t outbuff_max);

int ecall_borded_add_user(const char* in_buffer, char* out_buffer);

int ecall_border_remove_user(const char* in_buffer, char* out_buffer);

}
#endif
/* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */ 
/* end SGX border methods */
/* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */ 


unsigned char* sp_ibbe_create_group(
    std::vector<SpibbePartition>& partitions, 
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    std::vector<std::string>& members,
    int usersPerPartition);

int sp_ibbe_create_partition(
    SpibbePartition& partition, 
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    GroupKey gKey,
    std::vector<std::string>& members);

int sp_ibbe_add_user(
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    SpibbePartition& partition,
    std::string user_id);

int sp_ibbe_remove_user(
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    std::vector<SpibbePartition>& partitions,
    std::string user_id,
    int user_partition_index);

int sp_ibbe_user_decrypt(
    GroupKey* gKey,
    std::vector<EncryptedGroupKey>& gpKeys,
    std::vector<Ciphertext>& gpCiphers,
    PublicKey publicKey,
    UserPrivateKey userKey,
    std::string user_id,
    std::vector<std::string> members,
    int usersPerPartition);

/* OTHER */
int load_system(PublicKey& pk, ShortPublicKey& spk, MasterSecretKey& msk);


// SP_IBBE_H
#endif
