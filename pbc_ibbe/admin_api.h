#ifndef ADMIN_API_H
#define ADMIN_API_H

#include "sgx_ibbe.h"
#include "sgx_spibbe.h"

#if 0 // ignoring cloud stuff - Rafael
#include "cloud.h"
#else
struct Cloud {};
#endif

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

        void SystemSetup();
        void LoadSystem();
        PublicKey micro_get_pk() { return pk; }
        void micro_get_upk(std::string user_id, UserPrivateKey upk);
};

// ADMIN_API_H
#endif
