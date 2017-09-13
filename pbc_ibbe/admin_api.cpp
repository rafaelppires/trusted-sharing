#include "admin_api.h"
#include "spibbe.h"
#include "serialization.h"
#include "microbench.h"

// TODO : remove the include once implementation is finished. It's only used for print_hex.
#include "sgx_crypto.h"

std::string Configuration::CurveFile = "a.param";
int Configuration::UsersPerPartition;

SpibbeApi::SpibbeApi(std::string admin_name, Cloud* cloud)
{
    // system set-up
    char* s[2] = {"main\0", "a.param\0" };
    setup_sgx_safe(&(this->pk), &(this->spk), &(this->msk), Configuration::UsersPerPartition, 
        2, s);
        
    this->cloud = cloud;
}

void SpibbeApi::CreateGroup(std::string groupName, std::vector<std::string> groupMembers)
{
    std::vector<EncryptedGroupKey> gpKeys;
    std::vector<Ciphertext> gpCiphers;

    /* ------------ SP-IBBE ------------ */
#ifdef MICRO_CREATE
    struct timespec start, finish;
    start_clock
#endif 
    sp_ibbe_create_group(
        gpKeys, gpCiphers,
        this->spk, this->msk,
        groupMembers,
        Configuration::UsersPerPartition);      
#ifdef MICRO_CREATE
    end_clock(m0) 
#endif 

    /* ------------ SERIALIZATION ------------ */
#ifdef MICRO_CREATE 
    start_clock 
#endif 
    std::string s_members = serialize_members(groupMembers);
    std::string s_meta = serialize_group_metadata(gpKeys, gpCiphers);
#ifdef MICRO_CREATE
    end_clock(m1)
#endif 

    /* ------------ PUSH TO CLOUD ------------ */
#ifdef MICRO_CREATE
    start_clock
#endif 
    this->cloud->put_text(get_group_members_key(groupName), s_members);
    this->cloud->put_text(get_group_meta_key(groupName), s_meta);
#ifdef MICRO_CREATE
    end_clock(m2)
    printf("CREATE_GROUP,%d,%f,%f,%f,%d,%d\n", groupMembers.size(), m0, m1, m2, 
        s_members.size(), s_meta.size());
#endif 

}

void SpibbeApi::AddUserToGroup(std::string groupName, std::string userName)
{
#ifdef MICRO_ADD
    struct timespec start, finish;
    start_clock
#endif 
    // retreive data from cloud
    std::string k = get_group_members_key(groupName);
    std::string s_members = this->cloud->get_text(k);
    std::string s_meta = this->cloud->get_text(get_group_meta_key(groupName));
#ifdef MICRO_ADD
    end_clock(m0) 
#endif 

#ifdef MICRO_ADD
    start_clock
#endif 
    // deserialize
    std::vector<std::string> members;
    std::vector<EncryptedGroupKey> gpKeys;
    std::vector<Ciphertext> gpCiphers;
    deserialize_members(s_members, members);
    deserialize_group_metadata(s_meta, gpKeys, gpCiphers, this->spk.pairing);
#ifdef MICRO_ADD
    end_clock(m1) 
#endif 

#ifdef MICRO_ADD
    start_clock
#endif 
    // add user
    sp_ibbe_add_user(this->spk, this->msk, gpKeys, gpCiphers, members, userName,
        Configuration::UsersPerPartition);
#ifdef MICRO_ADD
    end_clock(m2) 
#endif 
    
#ifdef MICRO_ADD
    start_clock
#endif 
    // serialize 
    std::string new_s_members = serialize_members(members);
    std::string new_s_meta = serialize_group_metadata(gpKeys, gpCiphers);
#ifdef MICRO_ADD
    end_clock(m3) 
#endif 
    
#ifdef MICRO_ADD
    start_clock
#endif 
    // push to cloud
    this->cloud->put_text(get_group_members_key(groupName), s_members);
    this->cloud->put_text(get_group_meta_key(groupName), s_meta);
#ifdef MICRO_ADD
    end_clock(m4) 
    printf("ADD_MEMBER,%d,%f,%f,%f,%f,%f\n", members.size(), m0, m1, m2, m3, m4);
#endif 
}

void SpibbeApi::RemoveUserFromGroup(std::string groupName, std::string userName)
{
#ifdef MICRO_REMOVE
    struct timespec start, finish;
    start_clock
#endif 
    // retreive data from cloud
    std::string s_members = this->cloud->get_text(get_group_members_key(groupName));
    std::string s_meta = this->cloud->get_text(get_group_meta_key(groupName));
#ifdef MICRO_REMOVE
    end_clock(m0) 
#endif 

#ifdef MICRO_REMOVE
    start_clock
#endif 
    // deserialize
    std::vector<std::string> members;
    std::vector<EncryptedGroupKey> gpKeys;
    std::vector<Ciphertext> gpCiphers;
    deserialize_members(s_members, members);
    deserialize_group_metadata(s_meta, gpKeys, gpCiphers, this->spk.pairing);
#ifdef MICRO_REMOVE
    end_clock(m1) 
#endif 

#ifdef MICRO_REMOVE
    start_clock
#endif 
    // remove user
    sp_ibbe_remove_user(this->spk, this->msk, gpKeys, gpCiphers, members, userName,
        Configuration::UsersPerPartition);
#ifdef MICRO_REMOVE
    end_clock(m2) 
#endif 
    
#ifdef MICRO_REMOVE
    start_clock
#endif 
    // serialize 
    std::string new_s_members = serialize_members(members);
    std::string new_s_meta = serialize_group_metadata(gpKeys, gpCiphers);
#ifdef MICRO_REMOVE
    end_clock(m3) 
#endif 
    
#ifdef MICRO_REMOVE
    start_clock
#endif 
    // push to cloud
    this->cloud->put_text(get_group_members_key(groupName), s_members);
    this->cloud->put_text(get_group_meta_key(groupName), s_meta);
#ifdef MICRO_REMOVE
    end_clock(m4)
    printf("REMOVE_MEMBER,%d,%f,%f,%f,%f,%f\n", members.size(), m0, m1, m2, m3, m4);
#endif 
}

void SpibbeApi::micro_get_upk(std::string user_id, UserPrivateKey upk)
{
    extract_sgx_safe(this->spk, this->msk, upk, (char*) user_id.c_str());
}


/*
 * USER API ----------------------------------------------------------
 */
SpibbeUserApi::SpibbeUserApi(std::string user_name, Cloud* cloud, SpibbeApi* admin)
{
    this->user_name = user_name;
    this->cloud = cloud;
    this->pk = admin->micro_get_pk();
    admin->micro_get_upk(user_name, this->upk);
}

void SpibbeUserApi::GetGroupKey(std::string groupName, GroupKey* groupKey)
{
#ifdef MICRO_DECRYPT
    struct timespec start, finish;
    start_clock
#endif     
    // retreive data from cloud
    std::string s_members = this->cloud->get_text(get_group_members_key(groupName));
    std::string s_meta = this->cloud->get_text(get_group_meta_key(groupName));
#ifdef MICRO_DECRYPT
    end_clock(m0) 
#endif 

#ifdef MICRO_DECRYPT
    start_clock
#endif     
    // deserialize
    std::vector<std::string> members;
    std::vector<EncryptedGroupKey> gpKeys;
    std::vector<Ciphertext> gpCiphers;
    deserialize_members(s_members, members);
    deserialize_group_metadata(s_meta, gpKeys, gpCiphers, this->pk.pairing);
#ifdef MICRO_REMOVE
    end_clock(m1) 
#endif

#ifdef MICRO_DECRYPT
    start_clock
#endif         
    // decrypt 
    sp_ibbe_user_decrypt(groupKey, gpKeys, gpCiphers, 
        this->pk,
        this->upk,
        this->user_name,
        members, 
        Configuration::UsersPerPartition);
#ifdef MICRO_REMOVE
    end_clock(m2)
    printf("DECRYPT_KEY,%d,%f,%f,%f\n", members.size(), m0, m1, m2);
#endif 
}