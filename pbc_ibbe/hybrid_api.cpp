#include "hybrid_api.h"
#include "sgx_hybrid.h"
#include "serialization.h"
#include "microbench.h"

HybridApi::HybridApi(std::string admin_name, Cloud* cloud, bool useRsa)
{
    this->cloud = cloud;
    this->useRsa = useRsa;
}

HybridApi::~HybridApi()
{
}

void HybridApi::CreateGroup(std::string groupName, std::vector<std::string> groupMembers)
{
#ifdef MICRO_CREATE
    struct timespec start, finish;
    start_clock
#endif 
    // create group
    std::vector<std::string> encryptedKeys;
    hybrid_sgx_create_group(groupMembers, encryptedKeys, this->useRsa);
#ifdef MICRO_CREATE
    end_clock(m0) 
#endif 

#ifdef MICRO_CREATE 
    start_clock 
#endif 
    // serialization
    std::string s_members = serialize_members(groupMembers);
    std::string s_meta = serialize_hybrid_keys(encryptedKeys);
#ifdef MICRO_CREATE
    end_clock(m1)
#endif 

        /* ------------ PUSH TO CLOUD ------------ */
#ifdef MICRO_CREATE
    start_clock
#endif 
    //this->cloud->put_text(get_group_members_key(groupName), s_members);
    //this->cloud->put_text(get_group_meta_key(groupName), s_meta);
    // Stefan HACK: we have to converge to a single (members, meta) entity
    s_meta = "HYBRID_RSA\n" + s_members + "\n" + s_meta;
    this->cloud->put_text(get_group_meta_key(groupName), s_meta);
#ifdef MICRO_CREATE
    end_clock(m2)
    printf("%s_CREATE_GROUP,%d,%f,%f,%f,%d,%d\n", useRsa ? "RSA" : "ECC", groupMembers.size(), m0, m1, m2,
        s_members.size(), s_meta.size());
#endif 

}

/* ----------------------------------------------------------------------------- */
void HybridApi::AddUserToGroup(std::string groupName, std::string userName)
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
    std::vector<std::string> encryptedKeys;
    deserialize_members(s_members, members);
    deserialize_hybrid_keys(s_meta, encryptedKeys);
#ifdef MICRO_ADD
    end_clock(m1) 
#endif 

#ifdef MICRO_ADD
    start_clock
#endif 
    // add user
    hybrid_sgx_add_user(members, encryptedKeys, userName, this->useRsa);
#ifdef MICRO_ADD
    end_clock(m2) 
#endif 
    
#ifdef MICRO_ADD
    start_clock
#endif 
    // serialize 
    std::string new_s_members = serialize_members(members);
    std::string new_s_meta = serialize_hybrid_keys(encryptedKeys);
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
    printf("%s_ADD_MEMBER,%d,%f,%f,%f,%f,%f\n", useRsa ? "RSA" : "ECC", members.size(), m0, m1, m2, m3, m4);
#endif 
}

/* ----------------------------------------------------------------------------- */
void HybridApi::RemoveUserFromGroup(std::string groupName, std::string userName)
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
    std::vector<std::string> encryptedKeys;
    deserialize_members(s_members, members);
    deserialize_hybrid_keys(s_meta, encryptedKeys);
#ifdef MICRO_REMOVE
    end_clock(m1) 
#endif 

#ifdef MICRO_REMOVE
    start_clock
#endif 
    // remove user
    hybrid_sgx_remove_user(members, encryptedKeys, userName, this->useRsa);
#ifdef MICRO_REMOVE
    end_clock(m2) 
#endif 
    
    
#ifdef MICRO_REMOVE
    start_clock
#endif 
    // serialize 
    std::string new_s_members = serialize_members(members);
    std::string new_s_meta = serialize_hybrid_keys(encryptedKeys);
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
    printf("%s_REMOVE_MEMBER,%d,%f,%f,%f,%f,%f\n", useRsa ? "RSA" : "ECC", members.size(), m0, m1, m2, m3, m4);
#endif 
}