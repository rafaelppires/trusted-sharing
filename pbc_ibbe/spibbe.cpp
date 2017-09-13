/*
 *  TODO : The random and AES methods need to be replaced with the SGX ones.
 *  TODO : protect MSK by enclave private key.
 */

#include "sgx_crypto.h"
#include "ibbe.h"
#include "spibbe.h"
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include <vector>
#include <string>
#include <algorithm>

void sgx_random(int n, unsigned char b[])
{
    size_t i;
    for (i = 0; i < n; i++)
    {
        b[i] = (unsigned char) (rand() % 255 + 1);
    }
}

int get_partitions_count(std::vector<std::string>& members, int usersPerPartition)
{
    int totalPartitions = members.size() / usersPerPartition;
    if (usersPerPartition * totalPartitions < members.size())
    {
        totalPartitions++;
    }
    return totalPartitions;
}

int get_user_partition(std::vector<std::string>& members, std::string user_id, int usersPerPartition)
{
    //printf("Get user partitino \n");
    int pos = std::find(members.begin(), members.end(), user_id) - members.begin();
    //printf("%d\n", pos);
    if (pos < members.size())
    {
        return pos / usersPerPartition;
    }
    else
    {
        printf("ERROR the user is not part of the group !\n");
        return -1;
    }
}

int get_user_index(std::vector<std::string>& members, std::string user_id)
{
    int pos = std::find(members.begin(), members.end(), user_id) - members.begin();
    if (pos < members.size())
    {
        return pos;
    }
    else
    {
        printf("ERROR the user is not part of the group !\n");
        return -1;
    }
}

int sp_ibbe_create_group(
    std::vector<EncryptedGroupKey>& gpKeys,
    std::vector<Ciphertext>& gpCiphers,
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    std::vector<std::string> members,
    int usersPerPartition)
{
    // generate a random group key
    unsigned char* group_key = gen_random_bytestream(32);
    //printf("GKEY : "); print_hex(group_key, 32);

    // split idSet into partitions
    for (int p = 0; p * usersPerPartition < members.size(); p++)
    {
        int pStart = p * usersPerPartition;
        int pEnd   = pStart + usersPerPartition;
        if (pEnd > members.size())
        {
            pEnd = members.size();
        }

        char idPartition[pEnd - pStart][MAX_STRING_LENGTH];
        for (int i=pStart; i<pEnd; i++)
        {
            memcpy(idPartition[i - pStart], members[i].c_str(), MAX_STRING_LENGTH);
        }

        // get a broadcast and ciphertext for the partition
        BroadcastKey bKey;
        Ciphertext bCipher;
        encrypt_sgx_safe(&bKey, &bCipher, pubKey, msk, idPartition, pEnd - pStart); 

        // encrypt the group key by the broadcast key
        EncryptedGroupKey egk;
        sgx_random(16, egk.iv);
        sgx_aes_encrypt(group_key, 32, bKey, egk.iv, egk.encryptedKey);

        gpKeys.push_back(egk);
        gpCiphers.push_back(bCipher);
    }
}


int sp_ibbe_user_decrypt(
    GroupKey* gKey,
    std::vector<EncryptedGroupKey>& gpKeys,
    std::vector<Ciphertext>& gpCiphers,
    PublicKey publicKey,
    UserPrivateKey userKey,
    std::string user_id,
    std::vector<std::string> members,
    int usersPerPartition)
{
    int userPartition = get_user_partition(members, user_id, usersPerPartition);
    int totalPartitions = get_partitions_count(members, usersPerPartition);
    int idCount = usersPerPartition;
    if (userPartition == totalPartitions - 1)
    {
        idCount = members.size() - (userPartition * usersPerPartition);
    }

    char idSet[idCount][MAX_STRING_LENGTH];
    for (int i=0; i<idCount; i++)
    {
        int member_index = i + (usersPerPartition * userPartition);
        memcpy(idSet[i], members[member_index].c_str(), MAX_STRING_LENGTH);
    }

    // derive a broadcast key based on partition
    BroadcastKey bKey;
    decrypt_user(&bKey, gpCiphers[userPartition], publicKey, userKey,
        user_id.c_str(), idSet, idCount);

    // decrypt the encrypted group key by partition broadcast key
    sgx_aes_decrypt(gpKeys[userPartition].encryptedKey, 32, bKey,
        gpKeys[userPartition].iv, *gKey);
}

int sp_ibbe_add_user(
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    std::vector<EncryptedGroupKey>& gpKeys,
    std::vector<Ciphertext>& gpCiphers,
    std::vector<std::string>& members,
    std::string user_id,
    int usersPerPartition)
{
    // should we add to the last partition or create a new one
    if (members.size() % usersPerPartition == 0)
    {
        // get the group_key by decrypting by first partition
        // TODO : O(m) decrypt should be a theorem
        BroadcastKey bKey;
        char firstPartition[usersPerPartition][MAX_STRING_LENGTH];
        for (int i = 0; i < usersPerPartition; i++)
        {
            memcpy(firstPartition[i], members[i].c_str(), MAX_STRING_LENGTH);
        }
        decrypt_sgx_safe(&bKey, gpCiphers[0], pubKey, msk,
            firstPartition, usersPerPartition);

        // decrypt the group key
        GroupKey group_key;
        sgx_aes_decrypt(gpKeys[0].encryptedKey, 32, bKey,
            gpKeys[0].iv, group_key);

        // create new partition for a single user
        BroadcastKey singleUserBKey;
        Ciphertext bCipher;
        char idSet[1][MAX_STRING_LENGTH];
        memcpy(idSet[0], user_id.c_str(), MAX_STRING_LENGTH);
        encrypt_sgx_safe(&singleUserBKey, &bCipher, pubKey, msk, idSet, 1);

        // encrypt the group key by the new broadcast key
        EncryptedGroupKey egk;
        sgx_random(16, egk.iv);
        sgx_aes_encrypt(group_key, 32, singleUserBKey, egk.iv, egk.encryptedKey);

        gpKeys.push_back(egk);
        gpCiphers.push_back(bCipher);
    }
    else
    {
        // add to existing last partition
        int p = get_partitions_count(members, usersPerPartition);
        add_user_sgx_safe(pubKey, &(gpCiphers[p - 1]), msk, (char*) user_id.c_str());
    }
    members.push_back(user_id);
}


int sp_ibbe_remove_user(
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    std::vector<EncryptedGroupKey>& gpKeys,
    std::vector<Ciphertext>& gpCiphers,
    std::vector<std::string>& members,
    std::string user_id,
    int usersPerPartition)
{
    // generate new AES key
    unsigned char* group_key = gen_random_bytestream(32);

    // find the partition of the user
    int totalPartitions = get_partitions_count(members, usersPerPartition);
    int userPartition = get_user_partition(members, user_id, usersPerPartition);

    // for all the un-touched partitions, do an optimized re-key in O(1)
    for (int p = 0; p < totalPartitions; p++)
    {
        // skip user partition and last one, they are treated by special case below
        if (p != userPartition && p != totalPartitions - 1)
        {
            // re-key the broadcast key
            BroadcastKey bKey;
            rekey_sgx_safe(&bKey, &(gpCiphers[p]), pubKey, msk);

            // encrypt the new group key by broadcast key
            sgx_random(16, gpKeys[p].iv);
            sgx_aes_encrypt(group_key, 32, bKey, gpKeys[p].iv, gpKeys[p].encryptedKey);
        }
    }

    // remove user from user partition
    BroadcastKey user_partition_key;
    remove_user_sgx_safe(&user_partition_key, &(gpCiphers[userPartition]),
        (char*)user_id.c_str(),
        pubKey, msk);
    sgx_random(16, gpKeys[userPartition].iv);
    sgx_aes_encrypt(group_key, 32, user_partition_key,
        gpKeys[userPartition].iv, gpKeys[userPartition].encryptedKey);

    // add last member to the user partition
    std::string last_user = members[members.size() - 1];
    if (userPartition < totalPartitions)
    {
        // include last member in user partition
        add_user_sgx_safe(pubKey, &(gpCiphers[userPartition]), msk, (char*)last_user.c_str());

        // remove last member from last partition
        BroadcastKey last_partition_key;
        remove_user_sgx_safe(
            &last_partition_key,
            &(gpCiphers[totalPartitions - 1]),
            (char*) last_user.c_str(),
            pubKey, msk);
        sgx_random(16, gpKeys[totalPartitions - 1].iv);
        sgx_aes_encrypt(group_key, 32, last_partition_key,
            gpKeys[totalPartitions - 1].iv, gpKeys[totalPartitions - 1].encryptedKey);
    }

    // change the members list
    members[get_user_index(members, user_id)] = last_user;
    members.pop_back();

    // check if we need to get rid of last partition
    if (members.size() % usersPerPartition == 0)
    {
        gpKeys.pop_back();
        gpCiphers.pop_back();
    }
}
