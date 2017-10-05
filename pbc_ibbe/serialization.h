#ifndef SERIALIZATION_H
#define SERIALIZATION_H

#include "ibbe.h"
#include "spibbe.h"


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

/* SYS Serialization */
void serialize_public_key_to_file(PublicKey pk, std::string file_name);
void deserialize_public_key_from_file(std::string file_name, PublicKey& pk);

void serialize_short_public_key_to_file(ShortPublicKey spk, std::string file_name);
void deserialize_short_public_key_from_file(std::string file_name, ShortPublicKey& spk);

void serialize_msk_to_file(MasterSecretKey msk, std::string file_name);
void deserialize_msk_from_file(std::string file_name, MasterSecretKey& msk, pairing_t pairing);


/* OLD STUF ------------------------------------------------------- */



std::string serialize_members(std::vector<std::string>& members);
void deserialize_members(std::string s_members, std::vector<std::string>& members);

std::string serialize_group_metadata(std::vector<EncryptedGroupKey>& k, std::vector<Ciphertext>& c);
void deserialize_group_metadata(std::string s_meta, std::vector<EncryptedGroupKey>& k, std::vector<Ciphertext>& c, pairing_t pairing);

/* Hybrid Serialization */
std::string serialize_hybrid_keys(std::vector<std::string>& encryptedKeys);
void deserialize_hybrid_keys(std::string s, std::vector<std::string>& encryptedKeys);

/* Serialization to segmented chunks */
void serialize_members_chunks(std::vector<std::string>& members, std::vector<std::string>& ser_mem);
void serialize_meta_partition(std::vector<EncryptedGroupKey> k, std::vector<Ciphertext> c, std::vector<std::string>& ser_key);

/* SYSTEM PARAM SERIALIZATION */

std::string serialize_short_public_key(ShortPublicKey spk);
void deserialize_short_public_key(std::string s_spk, ShortPublicKey& spk);

std::string serialize_user_key();
void deserialize_user_key();

std::string serialize_master_secret_key();
void deserialize_master_secret_key();



#endif