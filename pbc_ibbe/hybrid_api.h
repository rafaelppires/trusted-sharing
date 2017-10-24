#ifndef HYBRID_API_H
#define HYBRID_API_H

#include "sgx_ibbe.h"
#include "sgx_spibbe.h"
#include "cloud.h"
#include "admin_api.h"

class HybridApi : public AdminApi
{
    private:
        bool useRsa;
        std::vector<std::string> encryptedKeys;
        std::vector<std::string> members;
    
            
    public:
        HybridApi(std::string admin_name, Cloud* cloud, bool useRsa = true);
        ~HybridApi();
        void SystemInit() {}
        void CreateGroup(std::string groupName, std::vector<std::string> groupMembers);
        void AddUserToGroup(std::string groupName, std::string userName);
        void RemoveUserFromGroup(std::string groupName, std::string userName);
};

// HYBRID_API_H
#endif