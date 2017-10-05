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

/* SHOULD RUN IN SGX */ 
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

// SHOULD NOT RUN IN SGX
int sp_ibbe_user_decrypt(
    GroupKey* gKey,
    std::vector<EncryptedGroupKey>& gpKeys,
    std::vector<Ciphertext>& gpCiphers,
    PublicKey publicKey,
    UserPrivateKey userKey,
    std::string user_id,
    std::vector<std::string> members,
    int usersPerPartition);


// SP_IBBE_H
#endif
