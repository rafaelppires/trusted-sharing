/*
 *  Admin Application. Untrusted Part.
 *  TODO :
 *      * move RedisCloud to own H file
 *      * construct a System Set-up method
 *      *
 *      * write methods to serialize
 *      * fill in the methods af admin api
 */

#include <cpp_redis/cpp_redis>
#include <iostream>
#include <string.h>

#include "pbc_ibbe/spibbe.h"
#include "pbc_ibbe/ibbe.h"

using namespace std;

class RedisCloud
{
    private:
        RedisCloud() {}
        static cpp_redis::redis_client client;

    public:
        static void Init()
        {
            client.connect("127.0.0.1", 6379, [](cpp_redis::redis_client&) {
              std::cout << "client disconnected (disconnection handler)" << std::endl;
            });
        }

        static void Bye()
        {
            client.disconnect();
        }

        static void PutText(std::string key, std::string value)
        {
            client.set(key, value);
            client.commit();
        }

        static std::string GetText(std::string key)
        {
            client.get(key, [](cpp_redis::reply& reply) {
                return reply.as_string();
            });
        }

        static void PutBinary(std::string key, unsigned char* data)
        {
            std::string s( reinterpret_cast< char const* >(data) ) ;
            client.set(key, s);
            client.commit();
        }

        static unsigned char* GetBinary(std::string key)
        {
            client.get(key, [](cpp_redis::reply& reply) {
                unsigned char *val = new unsigned char[reply.as_string().length() + 1];
                strcpy((char *)val, reply.as_string().c_str());
                return val;
            });
        }

        static void Commit()
        {
            client.sync_commit();
        }
};

cpp_redis::redis_client RedisCloud::client;


class AdminApp
{
    private:
        int i;

    public:

        AdminApp()
        {
            // load the system public_key

            // load the encrypted master key
        }

        void create_group(vector<string> user_names, string group_name);

        void add_user_to_group(string user_name, string group_name);

        void remove_user_from_group(string user_name, string group_name);
};

void AdminApp::create_group(vector<string> user_names, string group_name)
{
        // TODO : ...
}


int test_redis()
{
    std::cout << "REDIS CLOUD DEMO: " << std::endl;
    RedisCloud::Init();

    unsigned char a[] = {1, 2, 255, 4};
    RedisCloud::PutBinary("stefan", a);

    RedisCloud::Commit();
    RedisCloud::GetBinary("stefan");

    RedisCloud::Bye();
    return 0;
}


unsigned char* serialize_public_key(PublicKey pk)
{
    unsigned char* s = (unsigned char*) malloc(64);
    return s;
}

unsigned char* serialize_short_public_key(ShortPublicKey spk)
{
    unsigned char* s = (unsigned char*) malloc(64);
    return s;
}

unsigned char* serialize_master_secret_key(MasterSecretKey msk)
{
    unsigned char* s = (unsigned char*) malloc(64);
    return s;
}


int system_setup_beginning_of_time(int max_users_per_partition, vector<string> admin_enclaves_pub_keys)
{
    PublicKey pk;
    ShortPublicKey spk;
    MasterSecretKey msk;

    int c = 1;
    char* f = "a.param";
    setup_sgx_safe(&pk, &spk, &msk, max_users_per_partition, c, &f);
    // future improvement: the list of encalves_public_keys will be passed to the
    // method above and therefore msk will come back encrypted

    // serialize the keys
    unsigned char* s_pk = serialize_public_key(pk);
    unsigned char* s_spk = serialize_short_public_key(spk);
    unsigned char* s_msk = serialize_master_secret_key(msk);

    // store them on the cloud
    RedisCloud::Init();
    RedisCloud::PutBinary("pub_key", s_pk);
    RedisCloud::PutBinary("short_pub_key", s_spk);
    RedisCloud::PutBinary("master_secret_key", s_msk);
    RedisCloud::Commit();
    RedisCloud::Bye();

}




int main(void) {
    //test_redis();
    vector<string> enclave_pub_keys;
    system_setup_beginning_of_time(100, enclave_pub_keys);
    return 0;
}
