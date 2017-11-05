#include "sgx_serialize.h"

#include <string>

#ifndef ENABLE_SGX
#include <sstream>
#include <iostream>
#include <fstream>
#else
namespace stlpmtx_std {
    struct stringstream {
        stringstream () {}
        stringstream ( const std::string &s ) : buffer(s) {}

        void write( const char *p, size_t sz ) {
            buffer += std::string(p,sz);
        }

        void read( char *out, size_t sz ) {
            size_t rd = 0;
            memcpy(out, buffer.c_str(), rd=std::min(sz,buffer.size()) );
            buffer.erase(0,rd);
        }

        stringstream& operator<< (const std::string &in ) {
            buffer += in;
            return *this;
        }

        std::string str() { return buffer; }

        std::string buffer;
    };

    bool getline(stringstream &ss, std::string &s, char delim) {
        size_t nl = ss.buffer.find(delim);
        if( nl == std::string::npos ) {
            if( !ss.buffer.empty() ) {  
                s = ss.buffer;
                ss.buffer.clear();
                return true;
            } else {
                return false;
            }
        }
        s = ss.buffer.substr(0,nl);
        ss.buffer.erase(0,nl+1);
        return true;
    }
}
#endif

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

std::string serialize_partition_members(SpibbePartition partition)
{
    std::stringstream s;

    for(int i = 0; i < partition.members.size(); i++)
        s << partition.members[i] << "\n";
        
    return s.str();
}

std::string serialize_partition_meta(SpibbePartition p)
{
    // key
    std::stringstream s;
    s.write(reinterpret_cast< const char* >(&(p.encGroupKey.encryptedKey)), sizeof(p.encGroupKey.encryptedKey));
    s.write(reinterpret_cast< const char* >(&(p.encGroupKey.iv)), sizeof(p.encGroupKey.iv));            

    // cipher
    // c1
    int c1_size = element_length_in_bytes(p.ciphertext.c1);
    unsigned char* c1_bytes = (unsigned char*) malloc(c1_size);
    element_to_bytes(c1_bytes, p.ciphertext.c1);
    s.write(reinterpret_cast< const char* >(c1_bytes), c1_size);

    // c2
    int c2_size = element_length_in_bytes(p.ciphertext.c2);
    unsigned char* c2_bytes = (unsigned char*) malloc(c2_size);
    element_to_bytes(c2_bytes, p.ciphertext.c2);
    s.write(reinterpret_cast< const char* >(c2_bytes), c2_size);

    // h_pow_product_gamma_hash
    int c3_size = element_length_in_bytes(p.ciphertext.h_pow_product_gamma_hash);
    unsigned char* c3_bytes = (unsigned char*) malloc(c3_size);
    element_to_bytes(c3_bytes, p.ciphertext.h_pow_product_gamma_hash);
    s.write(reinterpret_cast< const char* >(c3_bytes), c3_size);

    return s.str();    
}

void deserialize_partition(SpibbePartition& p, std::string members, std::string meta, pairing_t pairing)
{
    if (members.size() != 0)
    {
        p.members.clear();
        std::stringstream s(members);
        std::string user;
        while(std::getline(s, user, '\n'))
        {
            p.members.push_back(user);
        }
    }
    
    if (meta.size() != 0)
    {
        std::stringstream s(meta);
    
        // key and iv
        s.read(reinterpret_cast<char*>(&(p.encGroupKey.encryptedKey)), sizeof(p.encGroupKey.encryptedKey));
        s.read(reinterpret_cast<char*>(&(p.encGroupKey.iv)), sizeof(p.encGroupKey.iv));
        
        
        int c_size = Configuration::CipherElemSize;
        // c1
        unsigned char c1_bytes[c_size] = {};
        s.read(reinterpret_cast<char*>(c1_bytes), c_size);
        element_init_G1(p.ciphertext.c1, pairing);
        element_from_bytes(p.ciphertext.c1, c1_bytes);
    
        // c2
        unsigned char c2_bytes[c_size];
        s.read(reinterpret_cast<char*>(c2_bytes), c_size);
        element_init_G1(p.ciphertext.c2, pairing);
        element_from_bytes(p.ciphertext.c2, c2_bytes);
        // c3
        unsigned char c3_bytes[c_size];
        s.read(reinterpret_cast<char*>(c3_bytes), c_size);
        element_init_G1(p.ciphertext.h_pow_product_gamma_hash, pairing);
        element_from_bytes(p.ciphertext.h_pow_product_gamma_hash, c3_bytes);
    }
}

#ifndef ENABLE_SGX
void serialize_public_key_to_file(PublicKey pk, std::string file_name)
{
    std::ofstream s(file_name);
    
    int w_size = element_length_in_bytes(pk.w);
    int v_size = element_length_in_bytes(pk.v);
    int h_size = element_length_in_bytes(pk.h[0]);
    
    int h_count = pk.h_size;
    s.write(reinterpret_cast<const char*>(&h_count), sizeof(h_count));

    unsigned char* w_bytes = (unsigned char*) malloc(w_size);
    element_to_bytes(w_bytes, pk.w);
    s.write(reinterpret_cast< const char* >(w_bytes), w_size);

    unsigned char* v_bytes = (unsigned char*) malloc(v_size);
    element_to_bytes(v_bytes, pk.v);
    s.write(reinterpret_cast< const char* >(v_bytes), v_size);

    for (int i=0; i<h_count; i++)
    {
        unsigned char* h_bytes = (unsigned char*) malloc(h_size);
        element_to_bytes(h_bytes, pk.h[i]);
        s.write(reinterpret_cast< const char* >(h_bytes), h_size);        
    }

    s.close();
}


void serialize_short_public_key_to_file(ShortPublicKey spk, std::string file_name)
{
    std::ofstream s(file_name);
    
    int w_size = element_length_in_bytes(spk.w);
    int v_size = element_length_in_bytes(spk.v);
    int h_size = element_length_in_bytes(spk.h);
    
    unsigned char* w_bytes = (unsigned char*) malloc(w_size);
    element_to_bytes(w_bytes, spk.w);
    s.write(reinterpret_cast< const char* >(w_bytes), w_size);

    unsigned char* v_bytes = (unsigned char*) malloc(v_size);
    element_to_bytes(v_bytes, spk.v);
    s.write(reinterpret_cast< const char* >(v_bytes), v_size);

    unsigned char* h_bytes = (unsigned char*) malloc(h_size);
    element_to_bytes(h_bytes, spk.h);
    s.write(reinterpret_cast< const char* >(h_bytes), h_size);        

    s.close();
}

void serialize_msk_to_file(MasterSecretKey msk, std::string file_name)
{
    std::ofstream s(file_name);
    
    int g_size = element_length_in_bytes(msk.g);
    int gamma_size = element_length_in_bytes(msk.gamma);

    unsigned char* g_bytes = (unsigned char*) malloc(g_size);
    element_to_bytes(g_bytes, msk.g);
    s.write(reinterpret_cast< const char* >(g_bytes), g_size);

    unsigned char* gamma_bytes = (unsigned char*) malloc(gamma_size);
    element_to_bytes(gamma_bytes, msk.gamma);
    s.write(reinterpret_cast< const char* >(gamma_bytes), gamma_size);

    s.close();
}

void deserialize_public_key_from_file(std::string file_name, PublicKey& pk)
{
    std::ifstream s(file_name);
    
    int h_count;
    s.read(reinterpret_cast<char*>(&h_count), sizeof(h_count));
    
    // read w (G1), v (GT), h
    // TODO : 128 should go in the global config
    int elem_size = 128;
    unsigned char w_bytes[elem_size];
    s.read(reinterpret_cast<char*>(w_bytes), elem_size);
    element_init_G1(pk.w, pk.pairing);
    element_from_bytes(pk.w, w_bytes);
    
    unsigned char v_bytes[elem_size];
    s.read(reinterpret_cast<char*>(v_bytes), elem_size);
    element_init_GT(pk.v, pk.pairing);
    element_from_bytes(pk.v, w_bytes);

    pk.h = (element_t*)malloc(sizeof(element_t) * (h_count + 1));    
    for(int i=0; i<h_count; i++)
    {
        unsigned char h_bytes[elem_size];
        s.read(reinterpret_cast<char*>(h_bytes), elem_size);
        element_init_G2(pk.h[i], pk.pairing);
        element_from_bytes(pk.h[i], h_bytes);
    }
    
    s.close();
}

void deserialize_short_public_key_from_file(std::string file_name, ShortPublicKey& spk)
{
    std::ifstream s(file_name);
    int elem_size = 128;
    unsigned char w_bytes[elem_size];
    s.read(reinterpret_cast<char*>(w_bytes), elem_size);
    element_init_G1(spk.w, spk.pairing);
    element_from_bytes(spk.w, w_bytes);
    
    unsigned char v_bytes[elem_size];
    s.read(reinterpret_cast<char*>(v_bytes), elem_size);
    element_init_GT(spk.v, spk.pairing);
    element_from_bytes(spk.v, w_bytes);
    
    unsigned char h_bytes[elem_size];
    s.read(reinterpret_cast<char*>(h_bytes), elem_size);
    element_init_G2(spk.h, spk.pairing);
    element_from_bytes(spk.h, h_bytes);

    s.close();
}

void deserialize_msk_from_file(std::string file_name, MasterSecretKey& msk, pairing_t pairing)
{
    std::ifstream s(file_name);

    int g_elem_size = 128;
    unsigned char g_bytes[g_elem_size];
    s.read(reinterpret_cast<char*>(g_bytes), g_elem_size);
    element_init_G1(msk.g, pairing);
    element_from_bytes(msk.g, g_bytes);
 
    // TODO : this should go to global config
    int z_elem_size = 20;
    unsigned char gamma_bytes[z_elem_size];
    s.read(reinterpret_cast<char*>(gamma_bytes), z_elem_size);
    element_init_Zr(msk.gamma, pairing);
    element_from_bytes(msk.gamma, gamma_bytes);

    s.close();
}
#endif


std::string serialize_spk_to_string(ShortPublicKey spk)
{
    std::stringstream s;
    
    int w_size = element_length_in_bytes(spk.w);
    int v_size = element_length_in_bytes(spk.v);
    int h_size = element_length_in_bytes(spk.h);
    
    unsigned char* w_bytes = (unsigned char*) malloc(w_size);
    element_to_bytes(w_bytes, spk.w);
    s.write(reinterpret_cast< const char* >(w_bytes), w_size);

    unsigned char* v_bytes = (unsigned char*) malloc(v_size);
    element_to_bytes(v_bytes, spk.v);
    s.write(reinterpret_cast< const char* >(v_bytes), v_size);

    unsigned char* h_bytes = (unsigned char*) malloc(h_size);
    element_to_bytes(h_bytes, spk.h);
    s.write(reinterpret_cast< const char* >(h_bytes), h_size);        

    return s.str();
}

void deserialize_spk_from_string(std::string in_s, ShortPublicKey& spk)
{
    std::stringstream s(in_s.c_str());
    int elem_size = 128;
    unsigned char w_bytes[elem_size];
    s.read(reinterpret_cast<char*>(w_bytes), elem_size);
    element_init_G1(spk.w, spk.pairing);
    element_from_bytes(spk.w, w_bytes);
    
    unsigned char v_bytes[elem_size];
    s.read(reinterpret_cast<char*>(v_bytes), elem_size);
    element_init_GT(spk.v, spk.pairing);
    element_from_bytes(spk.v, w_bytes);
    
    unsigned char h_bytes[elem_size];
    s.read(reinterpret_cast<char*>(h_bytes), elem_size);
    element_init_G2(spk.h, spk.pairing);
    element_from_bytes(spk.h, h_bytes);
}

std::string serialize_msk_to_string(MasterSecretKey msk)
{
    std::stringstream s;
    
    int g_size = element_length_in_bytes(msk.g);
    int gamma_size = element_length_in_bytes(msk.gamma);

    unsigned char* g_bytes = (unsigned char*) malloc(g_size);
    element_to_bytes(g_bytes, msk.g);
    s.write(reinterpret_cast< const char* >(g_bytes), g_size);

    unsigned char* gamma_bytes = (unsigned char*) malloc(gamma_size);
    element_to_bytes(gamma_bytes, msk.gamma);
    s.write(reinterpret_cast< const char* >(gamma_bytes), gamma_size);

    return s.str();
}

void deserialize_msk_from_string(std::string in_s, MasterSecretKey& msk, pairing_t pairing)
{
    std::stringstream s(in_s);

    int g_elem_size = 128;
    unsigned char g_bytes[g_elem_size];
    s.read(reinterpret_cast<char*>(g_bytes), g_elem_size);
    element_init_G1(msk.g, pairing);
    element_from_bytes(msk.g, g_bytes);
 
    // TODO : this should go to global config
    int z_elem_size = 20;
    unsigned char gamma_bytes[z_elem_size];
    s.read(reinterpret_cast<char*>(gamma_bytes), z_elem_size);
    element_init_Zr(msk.gamma, pairing);
    element_from_bytes(msk.gamma, gamma_bytes);
}

void deserialize_border_create_group(std::string s)
{
/* 
       // ---- deserialize from in_buffer
    // 1. short pub key, sealed msk
    ShortPublicKey spk;
    std::string s;
    deserialize_short_public_key_from_string(s, spk);
    
    MasterSecretKey msk;
    deserialize_msk_from_string(s, msk);
    
    // 2. members : vector<string>
    std::vector<std::string> members;
    // 3. users per partition : int
    int usersPerPartition;
*/
}


void serialize_create_group_input(ShortPublicKey spk, MasterSecretKey msk, std::vector<std::string> members, std::string& in_buffer)
{
    in_buffer = "";
    std::string s;
    
    in_buffer += serialize_spk_to_string(spk);
    // 284 BYTES
    // printf("\nSHORT PUB KEY LEN : %d\n", in_buffer.size());
    
    in_buffer += serialize_msk_to_string(msk);
    // 148 BYTES
    // printf("with MASTER SEC KEY : %d\n", in_buffer.size());
    
    in_buffer += serialize_members(members);
    // printf("with MEMBERS : %d\n", in_buffer.size());
}

void deserialize_create_group_input(std::string in_buffer, ShortPublicKey& spk, MasterSecretKey& msk, std::vector<std::string>& members)
{
    int SPK_LEN = 284;
    int MSK_LEN = 148;
    std::string s_spk = in_buffer.substr(0, SPK_LEN);
    std::string s_msk = in_buffer.substr(SPK_LEN, MSK_LEN);
    std::string s_members = in_buffer.substr(SPK_LEN + MSK_LEN, in_buffer.size() - (SPK_LEN + MSK_LEN));
    deserialize_spk_from_string(s_spk, spk);
    deserialize_msk_from_string(s_msk, msk, spk.pairing);
    deserialize_members(s_members, members);
}

void serialize_create_group_output(unsigned char* sealed_group_key, std::vector<SpibbePartition> partitions, std::string& out_buffer)
{
    out_buffer = "";
    std::string sgk((char*) sealed_group_key);
    out_buffer += sgk;
    for(int p=0; p < partitions.size(); p++)
    {
        // 432 BYTES / partition meta
        std::string s = serialize_partition_meta(partitions[p]);
        out_buffer += s;
        //printf("Meta size : %d\n", s.size());
    }
    
    // 2192 BYTES
    // printf("Out size : %d\n", out_buffer.size());
}
