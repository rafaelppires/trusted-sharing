#ifndef CLOUD_API_H
#define CLOUD_API_H

#include <cpp_redis/cpp_redis>
#include <string>

class Cloud
{
private:
    cpp_redis::redis_client client;
public:
    Cloud();
    ~Cloud();
    void put_text(std::string key, std::string value);
    std::string get_text(std::string key);
};

#endif // CLOUD_API_H