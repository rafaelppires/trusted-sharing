/*
 *  TODO : The random and AES methods need to be replaced with the SGX ones.
 *  TODO : protect MSK by enclave private key.
 */

#include "sgx_crypto.h"
#include "sgx_ibbe.h"
#include "sgx_spibbe.h"
#include "sgx_serialize.h"
//#include <pthread.h>
#include <unistd.h>

#include <vector>
#include <string>
#include <algorithm>

//#include "pbc_test.h"
int Configuration::UsersPerPartition = 2000;
const int Configuration::CipherElemSize;

#ifndef ENCLAVED
int load_system(PublicKey& pk, ShortPublicKey& spk, MasterSecretKey& msk)
{    
    // load paring file
    char s[16384], *fname = "a.param";
    FILE *fp = fopen(fname, "r");
    if( !fp ) {
        printf("Unable to open file %s\n", fname);
        return -1;
    }

    size_t count = fread(s, 1, 16384, fp);
    fclose(fp);    
    
    pairing_init_set_buf(spk.pairing, s, count);
    pairing_init_set_buf(pk.pairing, s, count);

    int error;
    if( deserialize_public_key_from_file("sys.pk", pk) ||
        deserialize_short_public_key_from_file("sys.spk", spk) ||
        deserialize_msk_from_file("sys.msk", msk, spk.pairing) ) {
        printf("Error reading key files\n");
        return -2;
    }

    return 0;
}
#endif

void fix_pairing(ShortPublicKey& spk)
{
    char s[16384] = "type a\n"
"q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n"
"h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n"
"r 730750818665451621361119245571504901405976559617\n"
"exp2 159\n"
"exp1 107\n"
"sign1 1\n"
"sign0 1\n";
    int count = 16384; 
    pairing_init_set_buf(spk.pairing, s, count);
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
        return -1;
    }
}

#if defined(ENCLAVED) || !defined(ENABLE_SGX)
int ecall_create_group(const char* in_buffer, size_t in_buffer_size, char* out_buffer, size_t outbuff_max)
{
    // deserialize the input buffer
    ShortPublicKey spk;
    MasterSecretKey msk;
    std::vector<std::string> members;
    std::string in_str;
    in_str.assign(in_buffer, in_buffer_size);
    fix_pairing(spk);
    deserialize_create_group_input(in_buffer, spk, msk, members);
    
    // call original SGX method
    std::vector<SpibbePartition> partitions;
    int usersPerPartition = Configuration::UsersPerPartition;
    unsigned char* group_key = 
        sp_ibbe_create_group(partitions, spk, msk, members, usersPerPartition);
    
    // TODO : seal group key by calling SGX api
    // ...
    
    // serialize output
    std::string out_s;
    serialize_create_group_output(group_key, partitions, out_s);
    // printf("serialize output size : %d\n", out_s.size());
    
    // deep copy to output buffer
    const std::string::size_type size = out_s.size();
    size_t ret;
    memcpy(out_buffer, out_s.c_str(), ret = std::min(outbuff_max,out_s.size()));
    return ret;
}

void sgx_borded_add_user(const char* in_buffer, char* out_buffer)
{
    // ...
}

void sgx_border_remove_user(const char* in_buffer, char* out_buffer)
{
    // ...
}
#endif

unsigned char* sp_ibbe_create_group(
    std::vector<SpibbePartition>& partitions,
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    std::vector<std::string>& members,
    int usersPerPartition)
{
    // generate a random group key
    unsigned char* group_key = gen_random_bytestream(32);
    // printf("GKEY : "); print_hex(group_key, 32);

    // split idSet into partitions
    for (int p = 0; p * usersPerPartition < members.size(); p++)
    {
        SpibbePartition partition;
        
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
            partition.members.push_back(members[i]);
        }

        // get a broadcast and ciphertext for the partition
        BroadcastKey bKey;
        encrypt_sgx_safe(&bKey, &(partition.ciphertext), pubKey, msk, idPartition, pEnd - pStart); 

        // encrypt the group key by the broadcast key
        sgx_random(16, partition.encGroupKey.iv);
        sgx_aes256_encrypt(group_key, 32, bKey, partition.encGroupKey.iv, partition.encGroupKey.encryptedKey);

        partitions.push_back(partition);
    }
    
    return group_key;
}

int sp_ibbe_create_partition(
    SpibbePartition& partition, 
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    GroupKey group_key,
    std::vector<std::string>& members)
{
    // HACK : scope of the method is currently for single users
    // create new partition for a single user
    BroadcastKey singleUserBKey;
    Ciphertext bCipher;
    char idSet[1][MAX_STRING_LENGTH];
    memcpy(idSet[0], members[0].c_str(), MAX_STRING_LENGTH);
    encrypt_sgx_safe(&singleUserBKey, &(partition.ciphertext), pubKey, msk, idSet, 1);

    // encrypt the group key by the new broadcast key
    EncryptedGroupKey egk;
    sgx_random(16, egk.iv);
    sgx_aes256_encrypt(group_key, 32, singleUserBKey, partition.encGroupKey.iv, partition.encGroupKey.encryptedKey);

    partition.members.push_back(members[0]);
}

int sp_ibbe_add_user(
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    SpibbePartition& partition,
    std::string user_id)
{
    add_user_sgx_safe(pubKey, &partition.ciphertext, msk, (char*) user_id.c_str());
    partition.members.push_back(user_id);
    return 0;
}

int sp_ibbe_remove_user(
    ShortPublicKey pubKey,
    MasterSecretKey msk,
    std::vector<SpibbePartition>& partitions,
    std::string user_id,
    int user_partition_index)
{
    // generate new AES key
    unsigned char* group_key = gen_random_bytestream(32);

    // for all un-touched partitions do an optimized re-key in O(1)
    for(int i=0; i<partitions.size(); i++)
        if (i != user_partition_index)
        {
            // re-key the broadcast key
            BroadcastKey bKey;
            rekey_sgx_safe(&bKey, &(partitions[i].ciphertext), pubKey, msk);

            // encrypt the new group key by broadcast key
            sgx_random(16, partitions[i].encGroupKey.iv);
            sgx_aes256_encrypt(group_key, 32, bKey, partitions[i].encGroupKey.iv, partitions[i].encGroupKey.encryptedKey);
        }

    // for user partition, do an optimized remove in O(1)
    BroadcastKey user_partition_key;
    remove_user_sgx_safe(&user_partition_key, &(partitions[user_partition_index].ciphertext),
        (char*)user_id.c_str(),
        pubKey, msk);
    sgx_random(16, partitions[user_partition_index].encGroupKey.iv);
    sgx_aes256_encrypt(group_key, 32, user_partition_key,
        partitions[user_partition_index].encGroupKey.iv, partitions[user_partition_index].encGroupKey.encryptedKey);
    if (partitions[user_partition_index].members.size() == 1)
    {
        partitions[user_partition_index].members.clear();
    }
    else
    {
        int usr_index = get_user_index(partitions[user_partition_index].members, user_id);
        int last_index = partitions[user_partition_index].members.size() - 1;
        partitions[user_partition_index].members[usr_index] = partitions[user_partition_index].members[last_index];
        partitions[user_partition_index].members.pop_back();
    }
}
