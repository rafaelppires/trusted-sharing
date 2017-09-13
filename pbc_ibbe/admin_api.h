#ifndef ADMIN_API_H
#define ADMIN_API_H

#include "ibbe.h"
#include "spibbe.h"
#include "cloud.h"

class AdminApi
{
    protected:
        std::string admin_name;
        Cloud* cloud;
            
    public:
        AdminApi() {}
        ~AdminApi() {}
        virtual void CreateGroup(std::string groupName, std::vector<std::string> groupMembers) = 0;
        virtual void AddUserToGroup(std::string groupName, std::string userName) = 0;
        virtual void RemoveUserFromGroup(std::string groupName, std::string userName) = 0;
};

class SpibbeApi : public AdminApi
{
    private:
        PublicKey pk;
        ShortPublicKey spk;
        MasterSecretKey msk;    
        
    public:
        SpibbeApi(std::string admin_name, Cloud* cloud);
        
        void CreateGroup(std::string groupName, std::vector<std::string> groupMembers);
        void AddUserToGroup(std::string groupName, std::string userName);
        void RemoveUserFromGroup(std::string groupName, std::string userName);

        PublicKey micro_get_pk() { return pk; }
        void micro_get_upk(std::string user_id, UserPrivateKey upk);
};

class UserApi
{
protected:
    std::string user_name;
    Cloud* cloud;
public:
    virtual void GetGroupKey(std::string groupName, GroupKey* groupKey) = 0;
};

class SpibbeUserApi : public UserApi
{
    private:
        PublicKey pk;
        UserPrivateKey upk;
        
    public:
        SpibbeUserApi(std::string user_name, Cloud* cloud, SpibbeApi* admin);
        ~SpibbeUserApi() {}
        void GetGroupKey(std::string groupName, GroupKey* groupKey);
};

class HybridUserApi : public UserApi
{
    public:
        HybridUserApi(std::string user_name, Cloud* cloud);
        ~HybridUserApi() {}
        void GetGroupKey(std::string groupName, GroupKey* groupKey);
};


class Configuration
{
    public:
        static int UsersPerPartition;
        static std::string CurveFile;
};

// ADMIN_API_H
#endif