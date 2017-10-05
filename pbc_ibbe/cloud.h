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
    
    virtual void put_multiple(std::vector<std::string> names, std::vector<std::string> content) = 0;
    virtual void get_multiple(std::vector<std::string> names, std::vector<std::string>& content) = 0;
        
    virtual void put_partition(std::string groupName, int partition, std::string members, std::string meta) = 0;
    virtual void get_partition(std::string groupName, int partition, std::string& members, std::string& meta) = 0;
    
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
    
    void put_multiple(std::vector<std::string> names, std::vector<std::string> content);
    void get_multiple(std::vector<std::string> names, std::vector<std::string>& content);

    void put_partition(std::string groupName, int partition, std::string members, std::string meta);
    void get_partition(std::string groupName, int partition, std::string& members, std::string& meta);

};

class DropboxCloud : public Cloud
{
public:
    DropboxCloud();
    ~DropboxCloud();
    void put_text(std::string key, std::string value);
    std::string get_text(std::string key);
    
    void put_multiple(std::vector<std::string> names, std::vector<std::string> content);
    void get_multiple(std::vector<std::string> names, std::vector<std::string>& content);
        
    void put_partition(std::string groupName, int partition, std::string members, std::string meta);
    void get_partition(std::string groupName, int partition, std::string& members, std::string& meta);
};

#endif // CLOUD_API_H