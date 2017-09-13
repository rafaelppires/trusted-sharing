#ifndef SP_IBBE_H
#define SP_IBBE_H

#include "ibbe.h"

#include <string>
#include <vector>

int sp_ibbe_create_group(
    std::vector<EncryptedGroupKey>& gpKeys,
    std::vector<Ciphertext>& gpCiphers,
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    std::vector<std::string> members,
    int usersPerPartition);

int sp_ibbe_add_user(
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    std::vector<EncryptedGroupKey>& gpKeys,
    std::vector<Ciphertext>& gpCiphers,
    std::vector<std::string>& members,
    std::string user_id,
    int usersPerPartition);

int sp_ibbe_remove_user(
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    std::vector<EncryptedGroupKey>& gpKeys,
    std::vector<Ciphertext>& gpCiphers,
    std::vector<std::string>& members,
    std::string user_id,
    int usersPerPartition);

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
