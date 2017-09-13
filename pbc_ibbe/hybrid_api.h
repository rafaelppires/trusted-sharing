#ifndef HYBRID_API_H
#define HYBRID_API_H

#include "ibbe.h"
#include "spibbe.h"
#include "cloud.h"
#include "admin_api.h"

class HybridApi : public AdminApi
{
    private:
        bool useRsa;
            
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