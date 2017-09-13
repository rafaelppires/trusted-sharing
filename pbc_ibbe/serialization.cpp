#include "serialization.h"

#include <string>
#include <iostream>
#include <sstream>

// TO BE REMOVER, it is only used for print_hex
#include "sgx_crypto.h"

std::string serialize_members(std::vector<std::string>& members)
{
    std::stringstream s;
    for(int i = 0; i < members.size(); i++)
        s << members[i] << "\n";
    return s.str();
}

void deserialize_members(std::string s_members, std::vector<std::string>& members)
{
    members.clear();
    std::stringstream s(s_members);
    std::string user;
    while(std::getline(s, user, '\n'))
    {
        members.push_back(user);
    }
}

std::string serialize_group_metadata(std::vector<EncryptedGroupKey>& k, std::vector<Ciphertext>& c)
{
    std::stringstream s;
    
    // header info : [count, c1_size, c2_size, c3_size]
    int count = k.size();
    s.write(reinterpret_cast< const char* >(&count), sizeof(count));
    int c1_size = element_length_in_bytes(c[0].c1);
    int c2_size = element_length_in_bytes(c[0].c2);
    int c3_size = element_length_in_bytes(c[0].h_pow_product_gamma_hash);
    s.write(reinterpret_cast< const char* >( &c1_size ), sizeof(c1_size));
    s.write(reinterpret_cast< const char* >( &c2_size ), sizeof(c2_size));
    s.write(reinterpret_cast< const char* >( &c3_size ), sizeof(c3_size));
    
    // list of (encrytped key, ciphers)
    for(int i = 0; i < k.size(); i++)
    {
        // key & iv
        s.write(reinterpret_cast< const char* >(&(k[i].encryptedKey)), sizeof(k[i].encryptedKey));
        s.write(reinterpret_cast< const char* >(&(k[i].iv)), sizeof(k[i].iv));
        
        // cipher
        // c1
        unsigned char* c1_bytes = (unsigned char*) malloc(c1_size);
        element_to_bytes(c1_bytes, c[i].c1);
        s.write(reinterpret_cast< const char* >(c1_bytes), c1_size);
    
        // c2
        unsigned char* c2_bytes = (unsigned char*) malloc(c2_size);
        element_to_bytes(c2_bytes, c[i].c2);
        s.write(reinterpret_cast< const char* >(c2_bytes), c2_size);
        // h_pow_product_gamma_hash
        unsigned char* c3_bytes = (unsigned char*) malloc(c3_size);
        element_to_bytes(c3_bytes, c[i].h_pow_product_gamma_hash);
        s.write(reinterpret_cast< const char* >(c3_bytes), c3_size);
    }
    
    return s.str();
}

void deserialize_group_metadata(std::string s_meta, std::vector<EncryptedGroupKey>& k, std::vector<Ciphertext>& c, pairing_t pairing)
{
    k.clear();
    c.clear();
    
    std::stringstream s(s_meta);
    
    // read header [count, c1_size, c2_size, c3_size]
    int count, c1_size, c2_size, c3_size;
    s.read(reinterpret_cast<char*>(&count), sizeof(count));
    s.read(reinterpret_cast<char*>(&c1_size), sizeof(c1_size));
    s.read(reinterpret_cast<char*>(&c2_size), sizeof(c2_size));
    s.read(reinterpret_cast<char*>(&c3_size), sizeof(c3_size));
    // read body
    for(int i=0; i<count; i++)
    {
        // key and iv
        EncryptedGroupKey egk;
        k.push_back(egk);
        s.read(reinterpret_cast<char*>(&(k[i].encryptedKey)), sizeof(k[i].encryptedKey));
        s.read(reinterpret_cast<char*>(&(k[i].iv)), sizeof(k[i].iv));
        
        // ciphers
        Ciphertext cipher;
        c.push_back(cipher);
        // c1
        unsigned char c1_bytes[c1_size] = {};
        s.read(reinterpret_cast<char*>(c1_bytes), c1_size);
        element_init_G1(c[i].c1, pairing);
        element_from_bytes(c[i].c1, c1_bytes);
        
        // c2
        unsigned char c2_bytes[c2_size];
        s.read(reinterpret_cast<char*>(c2_bytes), c2_size);
        element_init_G1(c[i].c2, pairing);
        element_from_bytes(c[i].c2, c2_bytes);
        // c3
        unsigned char c3_bytes[c3_size];
        s.read(reinterpret_cast<char*>(c3_bytes), c3_size);
        element_init_G1(c[i].h_pow_product_gamma_hash, pairing);
        element_from_bytes(c[i].h_pow_product_gamma_hash, c3_bytes);
    }
}

std::string serialize_hybrid_keys(std::vector<std::string>& encryptedKeys)
{
    std::stringstream s;
    
    int count = encryptedKeys.size();
    s.write(reinterpret_cast<const char*>(&count), sizeof(count));
    
    int size = encryptedKeys[0].size();
    s.write(reinterpret_cast<const char*>(&size), sizeof(size));
    
    for(int i=0; i<count; i++)
    {
        s.write(encryptedKeys[i].c_str(), size);
    }
    
    return s.str();
}

void deserialize_hybrid_keys(std::string s_ek, std::vector<std::string>& encryptedKeys)
{
    encryptedKeys.clear();

    std::stringstream s(s_ek);
    
    // read header [count, size]
    int count, size;
    s.read(reinterpret_cast<char*>(&count), sizeof(count));
    s.read(reinterpret_cast<char*>(&size), sizeof(size));
    
    // read encrypted keys
    for(int i=0; i<count; i++)
    {
        char ek[size];
        s.read(ek, size);
        std::string str_ek(ek, size);
        encryptedKeys.push_back(str_ek);
    }
}