#ifndef CLOUD_API_H
#define CLOUD_API_H

#include <cpp_redis/cpp_redis>
#include <string>

class Cloud
{
private:
    //
public:
    virtual void put_text(std::string key, std::string value) = 0;
    virtual std::string get_text(std::string key) = 0;
};

class RedisCloud : public Cloud
{
private:
    cpp_redis::redis_client client;
public:
    RedisCloud();
    ~RedisCloud();
    void put_text(std::string key, std::string value);
    std::string get_text(std::string key);
};

class DropboxCloud : public Cloud
{
public:
    DropboxCloud();
    ~DropboxCloud();
    void put_text(std::string key, std::string value);
    std::string get_text(std::string key);
};

#endif // CLOUD_API_H