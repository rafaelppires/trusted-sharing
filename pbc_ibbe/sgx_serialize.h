#ifndef SERIALIZATION_H
#define SERIALIZATION_H

#include "sgx_ibbe.h"
#include "sgx_spibbe.h"


inline std::string get_group_members_key(std::string groupName)
{
    return groupName + ".members";
}

inline std::string get_group_meta_key(std::string groupName)
{
    return groupName + ".meta";
}

/* SP-IBBE Serialization */
std::string serialize_partition_members(SpibbePartition partition);
std::string serialize_partition_meta(SpibbePartition partition);
void deserialize_partition(SpibbePartition& partition, std::string members, std::string meta, pairing_t pairing);

#ifndef ENCLAVED
/* SYS Serialization */
void serialize_public_key_to_file(PublicKey pk, std::string file_name);
int deserialize_public_key_from_file(std::string file_name, PublicKey& pk);

void serialize_short_public_key_to_file(ShortPublicKey spk, std::string file_name);
int deserialize_short_public_key_from_file(std::string file_name, ShortPublicKey& spk);

void serialize_msk_to_file(MasterSecretKey msk, std::string file_name);
int deserialize_msk_from_file(std::string file_name, MasterSecretKey& msk, pairing_t pairing);
#endif

/* Hybrid Serialization */
std::string serialize_hybrid_keys(std::vector<std::string>& encryptedKeys);
void deserialize_hybrid_keys(std::string s, std::vector<std::string>& encryptedKeys);
std::string serialize_members(std::vector<std::string>& members);
void deserialize_members(std::string s_members, std::vector<std::string>& members);


/* SYS Serialization TO STRING */
// TOOD : they should be merged with the file versions of serialization 
std::string serialize_spk_to_string(ShortPublicKey spk);
void deserialize_spk_from_string(std::string s, ShortPublicKey& spk);

std::string serialize_msk_to_string(MasterSecretKey msk);
void deserialize_msk_from_string(std::string s, MasterSecretKey& msk);


/* SGX BORDER SERIALIZATION METHODS */
void serialize_create_group_input(ShortPublicKey spk, MasterSecretKey msk, std::vector<std::string> members, std::string& in_buffer);
void deserialize_create_group_input(std::string in_buffer, ShortPublicKey& spk, MasterSecretKey& msk, std::vector<std::string>& members);
void serialize_create_group_output(unsigned char* sealed_group_key, std::vector<SpibbePartition> partitions, std::string& out_buffer);
//void deserialize_create_group_output(shortPubKey, msk, members, in_buffer);



#endif
