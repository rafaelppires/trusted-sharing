#include "cloud.h"
#include <fstream>
#include <string>
#include <iostream>
#include <sstream>

/* 
 *  Redis Cloud Methods -----------------------------------------------
 */

RedisCloud::RedisCloud()
{
    client.connect("127.0.0.1", 6379, [](cpp_redis::redis_client&) {
        printf("ER  ROR : Client Disconected !\n");
    });
}

RedisCloud::~RedisCloud()
{
    client.disconnect();
}

void RedisCloud::put_text(std::string key, std::string value)
{
    client.set(key, value);
    client.sync_commit();
}
    

std::string RedisCloud::get_text(std::string key)
{
    std::string value;
    client.get(key, [&value](cpp_redis::reply& reply) {
        value = reply.as_string();
    });
    client.sync_commit();
    return value;
}


/* 
 *  Dropbox Cloud Methods ----------------------------------------------
 */

DropboxCloud::DropboxCloud()
{
    // TODO : clear the cloud maybe?
}

DropboxCloud::~DropboxCloud()
{
}

void DropboxCloud::put_text(std::string key, std::string value)
{
    // serialize value to tmp file
    std::string tmp_filename = std::tmpnam(nullptr);
    std::ofstream out(tmp_filename);
    out << value;
    out.close();

    // zip the file, comment it for the moment
    /*
    std::string zip_command = "zip ";
    std::string zip_filename = std::tmpnam(nullptr);
    zip_command +=  zip_filename + " " + tmp_filename;
    system(zip_command.c_str());
    zip_filename += ".zip";
    */

    // upload tmp file to cloud
    std::string command = "python3 dbox.py upload ";
    command += key + " " + tmp_filename;
    //std::cout << command << "\n"; 
    system(command.c_str());
}
    

std::string DropboxCloud::get_text(std::string key)
{
    // download content from cloud
    std::string tmp_filename = std::tmpnam(nullptr);
    std::string command = "python3 dbox.py download ";
    command += key + " " + tmp_filename;
    //std::cout << command << "\n"; 
    system(command.c_str());
    
    // read file content into the returned string
    std::ifstream t(tmp_filename);
    std::stringstream buffer;
    buffer << t.rdbuf();
    return buffer.str();
}