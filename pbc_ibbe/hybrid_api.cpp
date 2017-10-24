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
    // create group
    this->members = groupMembers;
    hybrid_sgx_create_group(this->members, this->encryptedKeys, this->useRsa);

    if (this->cloud != NULL)
    {
        // serialization
        std::string s_members = serialize_members(this->members);
        std::string s_meta = serialize_hybrid_keys(this->encryptedKeys);

        // push to cloud
        s_meta = "HYBRID_RSA\n" + s_members + "\n" + s_meta;
        this->cloud->put_text(get_group_meta_key(groupName), s_meta);
    }
    
    printf("Hybrid Group Created !\n");
}

/* ----------------------------------------------------------------------------- */
void HybridApi::AddUserToGroup(std::string groupName, std::string userName)
{
    // retreive data from admin cache
    std::string k = get_group_members_key(groupName);

    // add user
    hybrid_sgx_add_user(this->members, this->encryptedKeys, userName, this->useRsa);

    if (this->cloud != NULL)
    {
        // serialize 
        std::string new_s_members = serialize_members(this->members);
        std::string new_s_meta = serialize_hybrid_keys(this->encryptedKeys);

        // push to cloud
        this->cloud->put_text(get_group_members_key(groupName), new_s_members);
        this->cloud->put_text(get_group_meta_key(groupName), new_s_meta);
    }
}

/* ----------------------------------------------------------------------------- */
void HybridApi::RemoveUserFromGroup(std::string groupName, std::string userName)
{
   /// printf("Remove %s\n", userName.c_str());
    // remove user
    hybrid_sgx_remove_user(this->members, this->encryptedKeys, userName, this->useRsa);    
    
    if (this->cloud != NULL)
    {
        // serialize 
        std::string new_s_members = serialize_members(members);
        std::string new_s_meta = serialize_hybrid_keys(encryptedKeys);

        // push to cloud
        this->cloud->put_text(get_group_members_key(groupName), new_s_members);
        this->cloud->put_text(get_group_meta_key(groupName), new_s_meta);
    }
}