#include "admin_api.h"
#include "sgx_spibbe.h"
#include "serialization.h"
#include "microbench.h"
#include "admin_cache.h"
#include "pbc_test.h"

// TODO : remove the include once implementation is finished. It's only used for print_hex.
#include "sgx_crypto.h"

std::string Configuration::CurveFile = "a.param";
int Configuration::UsersPerPartition;

SpibbeApi::SpibbeApi(std::string admin_name, Cloud* cloud)
{
    SystemSetup();
    //LoadSystem();
    this->cloud = cloud;
    AdminCache::ClearAll();
}

void SpibbeApi::SystemSetup()
{
    // load paring file
    char s[16384];
    FILE *fp = fopen("a.param\0", "r");
    size_t count = fread(s, 1, 16384, fp);
    if (!count) pbc_die("input error");
    fclose(fp);    
    
    setup_sgx_safe(&(this->pk), &(this->spk), &(this->msk), Configuration::UsersPerPartition, 
        s, count);

    serialize_public_key_to_file(this->pk, "sys.pk");
    serialize_short_public_key_to_file(this->spk, "sys.spk");
    serialize_msk_to_file(this->msk, "sys.msk");
}

void SpibbeApi::LoadSystem()
{
    char* s[2] = {"main\0", "a.param\0" };
    
    pbc_demo_pairing_init(this->pk.pairing, 2, s);
    pbc_demo_pairing_init(this->spk.pairing, 2, s);

    deserialize_public_key_from_file("sys.pk", this->pk);
    deserialize_short_public_key_from_file("sys.spk", this->spk);
    deserialize_msk_from_file("sys.msk", this->msk, this->spk.pairing);
}

void SpibbeApi::CreateGroup(std::string groupName, std::vector<std::string> groupMembers)
{
    printf("-----> START CREATE GROUP \n");
    
    std::vector<SpibbePartition> partitions;

    /* ------------ SP-IBBE ------------ */
    unsigned char* g_key = sp_ibbe_create_group(
        partitions,
        this->spk, this->msk,
        groupMembers,
        Configuration::UsersPerPartition);      
    //printf("returned value "); print_hex(g_key, 32);

    
    if (this->cloud != NULL)
    {
        // serialization
        std::vector<std::string> names;
        std::vector<std::string> content;
        for (int p=0; p<partitions.size(); p++)
        {
            names.push_back(groupName + "/p" + std::to_string(p) + "/members.txt");
            content.push_back(serialize_partition_members(partitions[p]));
            
            names.push_back(groupName + "/p" + std::to_string(p) + "/meta.txt");
            content.push_back(serialize_partition_meta(partitions[p]));
        }
        
        // push to cloud
        this->cloud->put_multiple(names, content);
    }
    
    // push to local cache
    for (int p=0; p<partitions.size(); p++)
    {
        AdminCache::TryCacheIncompletePartition(groupName, p, partitions[p]);
        for (int i=0; i<partitions[p].members.size(); i++)
            AdminCache::PutUserPartition(groupName, partitions[p].members[i], p);
    }
    memcpy(AdminCache::EnclaveGroupKey[groupName], g_key, 32);
            
    printf("-----> GROUP CREATED \n");
}

void SpibbeApi::AddUserToGroup(std::string groupName, std::string userName)
{
    //printf("-----> START ADD USER TO GROUP \n");
 
    // find a non-empty partition for the user
    bool is_new_partition;
    int p = AdminCache::FindAvailablePartition(groupName, is_new_partition);

    SpibbePartition partition;
    if (!is_new_partition)
    {
        // retreive partition from incomplete partitions cache
        partition = AdminCache::GetCachedIncompletePartition(groupName, p);
        
        // SPIBBE - add user
        sp_ibbe_add_user(this->spk, this->msk, partition, userName);        
    }
    else
    {
        // retreive enclave protected key
        printf("returned value "); print_hex(AdminCache::EnclaveGroupKey[groupName], 32);
        
        // create a one user partition
        std::vector<std::string> singleMember;
        singleMember.push_back(userName);
        sp_ibbe_create_partition(partition, this->spk, this->msk, AdminCache::EnclaveGroupKey[groupName], singleMember);
    }
         
    if (this->cloud != NULL)
    {
        // serialize 
        std::string new_s_members = serialize_partition_members(partition);
        std::string new_s_meta = serialize_partition_meta(partition);
        
        // push to cloud
        this->cloud->put_partition(groupName, p, new_s_members, new_s_meta);        
    }
    
    // push to admin cache
    AdminCache::PutUserPartition(groupName, userName, p);
    AdminCache::TryCacheIncompletePartition(groupName, p, partition);
 
    //printf("-----> USER ADDED \n");
}

void SpibbeApi::RemoveUserFromGroup(std::string groupName, std::string userName)
{
    //printf("-----> START REMOVE USER FROM GROUP \n");

    // get user partition
    int p = AdminCache::GetUserPartition(groupName, userName);
    int total_partitions = AdminCache::GetPartitionsCount(groupName);
    
    std::vector<SpibbePartition> partitions;
    for(int i=0; i<total_partitions; i++)
    {
        partitions.push_back(AdminCache::GetCachedIncompletePartition(groupName, i));
    }
        
    // remove user from current partition, re-key for the rest
    sp_ibbe_remove_user(this->spk, this->msk, partitions, userName, p);    
    
    if (this->cloud)
    {
        // serialize all and push to cloud
        std::vector<std::string> names;
        std::vector<std::string> content;
        for (int i=0; i<partitions.size(); i++)
        {
            if (i == p)
            {
                names.push_back(groupName + "/p" + std::to_string(i) + "/members.txt");
                content.push_back(serialize_partition_members(partitions[i]));
            }
            names.push_back(groupName + "/p" + std::to_string(i) + "/meta.txt");
            content.push_back(serialize_partition_meta(partitions[i]));
        }

        // push to cloud
        this->cloud->put_multiple(names, content);
    }

    // push partitions to cache
    for (int i=0; i<partitions.size(); i++)
    {
        AdminCache::TryCacheIncompletePartition(groupName, p, partitions[p]);
    }

    // cache changes
    AdminCache::RemoveUserFromPartition(groupName, userName, p);
    //printf("-----> USER REMOVED \n");
    
    AdminCache::PrintPartitions(groupName);
}

void SpibbeApi::micro_get_upk(std::string user_id, UserPrivateKey upk)
{
    extract_sgx_safe(this->spk, this->msk, upk, (char*) user_id.c_str());
}