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
std::string serialize_members(std::vector<std::string>& members);
void deserialize_members(std::string s_members, std::vector<std::string>& members);

std::string serialize_group_metadata(std::vector<EncryptedGroupKey>& k, std::vector<Ciphertext>& c);
void deserialize_group_metadata(std::string s_meta, std::vector<EncryptedGroupKey>& k, std::vector<Ciphertext>& c, pairing_t pairing);

std::string serialize_public_key(PublicKey pk);
void deserialize_public_key(std::string s_pk, PublicKey& pk);

std::string serialize_short_public_key(ShortPublicKey spk);
void deserialize_short_public_key(std::string s_spk, ShortPublicKey& spk);

std::string serialize_user_key();
void deserialize_user_key();

std::string serialize_master_secret_key();
void deserialize_master_secret_key();

/* Hybrid Serialization */
std::string serialize_hybrid_keys(std::vector<std::string>& encryptedKeys);
void deserialize_hybrid_keys(std::string s, std::vector<std::string>& encryptedKeys);

#endif