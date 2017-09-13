#ifndef MICROBENCH_H
#define MICROBENCH_H

#include <time.h>
#include "admin_api.h"
#include "hybrid_api.h"
#include "tests.h"

// TODO : optimal value is 17. Keep 10 for testing.
#define MICRO_POINTS 17

#define MICRO_CREATE
#define MICRO_ADD
#define MICRO_REMOVE
#define MICRO_DECRYPT

#define start_clock clock_gettime(CLOCK_MONOTONIC, &start);
#define end_clock(m) clock_gettime(CLOCK_MONOTONIC, &finish); double m = (finish.tv_sec - start.tv_sec) + ((finish.tv_nsec - start.tv_nsec) / 1000000000.0);

static inline void microbenchmarks()
{
    Configuration::UsersPerPartition = 2000;
    std::string u = "test0@mail.com";
    std::string a = "master";
    
    //Cloud* c = new RedisCloud();
    Cloud* c = new DropboxCloud();
    
    SpibbeApi* spibbeAdmin = new SpibbeApi(a, c);
    HybridApi* hybridAdmin = new HybridApi(a, c);
    
    SpibbeUserApi* spibbeUser = new SpibbeUserApi(u, c, spibbeAdmin);
    HybridUserApi* hybridUser = new HybridUserApi(u, c);

    micro_create_group(spibbeAdmin);
    micro_create_group(hybridAdmin);
  
    micro_add_user(spibbeAdmin);
    micro_add_user(hybridAdmin);
    
    micro_remove_user(spibbeAdmin);
    micro_remove_user(hybridAdmin);
    
    micro_decrypt_key(spibbeAdmin, spibbeUser);
    micro_decrypt_key(hybridAdmin, hybridUser);
}


// MICROBENCH_H
#endif