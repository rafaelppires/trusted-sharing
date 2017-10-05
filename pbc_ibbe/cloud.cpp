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

void RedisCloud::put_multiple(std::vector<std::string> names, std::vector<std::string> content)
{
    // ...
}

void RedisCloud::get_multiple(std::vector<std::string> names, std::vector<std::string>& content)
{
   // ... 
}


void RedisCloud::put_partition(std::string groupName, int partition, std::string members, std::string meta)
{
    // TODO : ...
}

void RedisCloud::get_partition(std::string groupName, int partition, std::string& members, std::string& meta)
{
    // TODO : ....
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
    tmp_filename = zip_filename + ".zip";
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

void DropboxCloud::put_multiple(std::vector<std::string> names, std::vector<std::string> content)
{
    std::vector<std::string> local_files;

    // put the files on the local fs and let dropbox python pick them up
    for(int i=0; i<names.size(); i++)
    {
        // serialize value to tmp file
        std::string tmp_filename = std::tmpnam(nullptr);
        std::ofstream out(tmp_filename);
        out << content[i];
        out.close();
        
        local_files.push_back(tmp_filename);
    }

    // save file_list to a text file, with line formats:
    std::string list_filename = std::tmpnam(nullptr);
    std::ofstream out_list(list_filename);
    for (int i=0; i<names.size(); i++)
    {
        out_list << names[i] << "," << local_files[i] <<"\n";
    }    
    out_list.close();
    
    //printf("FILE WITH LIST : %s\n", list_filename.c_str());
    std::string command = "python3 dbox.py put_multiple ";
    command += list_filename + " tmp";
    system(command.c_str());
}

void DropboxCloud::get_multiple(std::vector<std::string> names, std::vector<std::string>& content)
{
    // serialize request list to file
    std::vector<std::string> local_names;
    std::string request_list = std::tmpnam(nullptr);
    std::ofstream out_list(request_list);
    for(int i=0; i<names.size(); i++)
    {
        std::string tmp_filename = std::tmpnam(nullptr);
        out_list << names[i] << "," << tmp_filename <<"\n";
        std::cout << names[i] << "," << tmp_filename << "\n";
        local_names.push_back(tmp_filename);
    }
    out_list.close();
    
    // download list from cloud
    std::string tmp_filename = std::tmpnam(nullptr);
    std::string command = "python3 dbox.py download_multiple ";
    command += request_list + " tmp";
    //std::cout << command << "\n"; 
    system(command.c_str());
    
    // load all downloaded content in the returned map
    content.clear();
    for(int i=0; i<names.size(); i++)
    {
        std::ifstream t(local_names[i]);
        std::stringstream buffer;
        buffer << t.rdbuf();
        content.push_back(buffer.str());    
    } 
}


void DropboxCloud::put_partition(std::string groupName, int partition, std::string members, std::string meta)
{
    // is this worth for parallelization?
    std::string partition_members_file = groupName + "/p" + std::to_string(partition) + "/members.txt";
    std::string partition_meta_file = groupName + "/p" + std::to_string(partition) + "/meta.txt";
    this->put_text(partition_members_file, members);
    this->put_text(partition_meta_file, meta);
}

void DropboxCloud::get_partition(std::string groupName, int partition, std::string& members, std::string& meta)
{
    // is this worth for parallelization?
    std::string partition_members_file = groupName + "/p" + std::to_string(partition) + "/members.txt";
    std::string partition_meta_file = groupName + "/p" + std::to_string(partition) + "/meta.txt";
    members = this->get_text(partition_members_file);
    meta = this->get_text(partition_meta_file);
}