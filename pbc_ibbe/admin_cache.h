#ifndef ADMIN_CACHE_H
#define ADMIN_CACHE_H

#include<string>
#include <stdlib.h>
#include <time.h>

// Admin Caches :
//  (1) User Partition Index, given: (group, user id)
//  (2) Free Space per Partition, given (group)
//  (3) Not-full partitions - speed up addition
// ?(4) All metadata items - speed up removal
// TODO : move admin cache to CPP

class AdminCache
{
private:
    // key = (group.user), value = partition_index 
    static std::map<std::string, int> userPartitions;
    
    // key = group, value = [2000 2000 2000 .... ]
    static std::map<std::string, std::vector<int>> partitionOccupancy;
    
    // key - (group.user), value = SpibbePartition
    static std::map<std::string, SpibbePartition> incompletePartitions;
    
public:

    static std::map<std::string, GroupKey> EnclaveGroupKey;

    AdminCache() {}
    
    static inline void PutUserPartition(std::string group, std::string user, int partitionIndex)
    {
        std::string key = group + "." + user;
        AdminCache::userPartitions[key] = partitionIndex;
        if (partitionIndex + 1> partitionOccupancy[group].size())
        {
             partitionOccupancy[group].resize(partitionIndex + 1);
        }
        partitionOccupancy[group][partitionIndex]++;
    }
  
    static inline int GetUserPartition(std::string group, std::string user)
    {
        std::string key = group + "." + user;
        return AdminCache::userPartitions[key];
    }
    
    static inline int GetPartitionsCount(std::string group)
    {
        return partitionOccupancy[group].size();
    }
    
    static inline int RemoveUserFromPartition(std::string group, std::string user, int partitionIndex)
    {
        partitionOccupancy[group][partitionIndex]--;
        
        std::string key = group + "." + user;
        userPartitions.erase(key);
    }
    
    static inline int FindAvailablePartition(std::string group, bool& is_new_partition)
    {
        // debug : list partitions
        /*
        printf("Finding available partition ...");
        for(int i=0; i<partitionOccupancy[group].size(); i++)
            printf("%d ", partitionOccupancy[group][i]);
        
         */
        // end debug list
    
        // select random non empty partition
        srand ( time(NULL) );
        int start_random = rand() % partitionOccupancy[group].size();
        int r = start_random;
        is_new_partition = false;
        while (partitionOccupancy[group][r] == Configuration::UsersPerPartition)
        {
            r++;
            if (r == partitionOccupancy[group].size())
            {
                r = 0;
            }
            if (r == start_random)
            {
                is_new_partition = true;
                break;
            }
        }
        if (is_new_partition)
        {
            return partitionOccupancy[group].size();
        }
        else
        {
            return r;
        }
    }
    
    static void TryCacheIncompletePartition(std::string g, int p, SpibbePartition partition)
    {
        std::string k = g + "." + std::to_string(p);
        incompletePartitions[k] = partition;
    }
    
    static SpibbePartition GetCachedIncompletePartition(std::string g, int p)
    {
        std::string k = g + "." + std::to_string(p);
        return incompletePartitions[k];        
    }
    
    static void ClearAll()
    {
        userPartitions.clear();
        partitionOccupancy.clear();
        EnclaveGroupKey.clear();
        incompletePartitions.clear();
    }
    
    static void PrintPartitions(std::string g)
    {
        printf("PARTITIONS : %d\n", partitionOccupancy[g].size());
        for(int i=0; i<partitionOccupancy[g].size(); i++)
            printf("[%d] ", partitionOccupancy[g][i]);
        printf("\n");
    }
};

std::map<std::string, int> AdminCache::userPartitions;
std::map<std::string, std::vector<int>> AdminCache::partitionOccupancy;
std::map<std::string, GroupKey> AdminCache::EnclaveGroupKey;
std::map<std::string, SpibbePartition> AdminCache::incompletePartitions;
    
#endif // ADMIN_CACHE_H