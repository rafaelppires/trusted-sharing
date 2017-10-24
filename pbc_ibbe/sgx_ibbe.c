/*
 *  Implementation of SP-IBBE,
 *  i.e. Secured & Partitioned - Identity Based Broadcast Encryption.
 *
 *  Author: Stefan Contiu <stefan.contiu@u-bordeaux.fr>
 *
 *  Published under Apache v2 License:
 *      https://www.apache.org/licenses/LICENSE-2.0.txt
 */

#include "sgx_ibbe.h"
#include "pbc_test.h"
#include "sgx_crypto.h"
//#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>


int setup_sgx_safe(PublicKey *puk, ShortPublicKey *spuk, MasterSecretKey *msk, int max_group_size, 
            const char* pairing_string, size_t pairing_string_len)
{
    int i;
    element_t g, h;
    element_t w, v;
    element_t gamma;
    element_t temp1;
    element_t *hRec;

    // load pairing from arguments
    {
        srand(time(NULL));
        pbc_random_set_deterministic(rand());

        pairing_init_set_buf(spuk->pairing, pairing_string, pairing_string_len);
        pairing_init_set_buf(puk->pairing, pairing_string, pairing_string_len);
        // pbc_demo_pairing_init(spuk->pairing, argc, argv);
        // pbc_demo_pairing_init(puk->pairing, argc, argv);
    }

    element_init_G1(g, spuk->pairing);
    element_init_G2(h, spuk->pairing);
    element_init_G1(w, spuk->pairing);
    element_init_GT(v, spuk->pairing);
    element_init_Zr(gamma, spuk->pairing);
    element_init_Zr(temp1, spuk->pairing);

    // generate random values
    {
        element_random(g);
        element_random(h);
        element_random(gamma);
    }

    // compute w and v
    {
        element_pow_zn(w, g, gamma);
        element_pairing(v, g, h);
    }

    // compute public key h sequence
    {
        hRec = (element_t*)malloc(sizeof(element_t) * (max_group_size + 2));
        mpz_t n;
        mpz_init(n);
        for (i = 0; i <= max_group_size; i++)
        {
            element_init_G2(hRec[i], spuk->pairing);
            mpz_set_ui(n, (unsigned int)i);
            element_pow_mpz(temp1, gamma, n);
            element_pow_zn(hRec[i], h, temp1);
        }
        mpz_clear(n);

        puk->h = hRec;
        puk->h_size = max_group_size + 1;
        element_init_G1(puk->w, spuk->pairing);
        element_init_GT(puk->v, spuk->pairing);
        element_set(puk->w, w);
        element_set(puk->v, v);
    }

    // define master secret key
    {
        element_init_G1(msk->g, spuk->pairing);
        element_init_Zr(msk->gamma, spuk->pairing);
        element_set(msk->g, g);
        element_set(msk->gamma, gamma);
    }

    // define the short SGX safe public key
    {
        element_init_G1(spuk->w, spuk->pairing);
        element_init_GT(spuk->v, spuk->pairing);
        element_init_G1(spuk->h, spuk->pairing);
        element_set(spuk->w, puk->w);
        element_set(spuk->v, puk->v);
        element_set(spuk->h, puk->h[0]);
        int hlen = element_length_in_bytes(puk->h[0]);
    }

    // clean-up
    element_clear(h);
    element_clear(temp1);

    return 0;
}

int extract_sgx_safe(ShortPublicKey spk, MasterSecretKey msk, UserPrivateKey idkey, char* id)
{
    element_t hid;
    element_init_Zr(hid, spk.pairing);
    element_init_G1(idkey, spk.pairing);

    // compute gamma + hash
    element_from_hash(hid, id, strlen(id));
    element_add(hid, hid, msk.gamma);

    // invert and exponentiate g
    element_invert(hid, hid);
    element_pow_zn(idkey, msk.g, hid);

    element_clear(hid);
    return 0;
}


int encrypt_sgx_safe(BroadcastKey* bKey, Ciphertext *cipher,
    ShortPublicKey pubKey, MasterSecretKey msk, char idSet[][MAX_STRING_LENGTH], int idCount)
{
    element_t k;
    element_t c1, c2, c3;
    element_t product;
    element_t hash;

    element_init_Zr(k, pubKey.pairing);
    element_init_G1(c1, pubKey.pairing);
    element_init_G2(c2, pubKey.pairing);
    element_init_G2(c3, pubKey.pairing);
    element_random(k);

    // compute C1
    {
        element_pow_zn(c1, pubKey.w, k);
        element_invert(c1, c1);
    }

    // compute C2 and C3
    {
        element_init_Zr(product, pubKey.pairing);
        element_set1(product);
        for (int i = 0; i < idCount; i++)
        {
            // compute hash
            element_init_Zr(hash, pubKey.pairing);
            element_from_hash(hash, idSet[i], strlen(idSet[i]));

            // sum hash with gamma and multiply into product
            element_add(hash, msk.gamma, hash);
            element_mul(product, product, hash);
        }

        // raise h at product
        element_pow_zn(c3, pubKey.h, product);

        // raise c3 at k
        element_pow_zn(c2, c3, k);
   }

    // compute BroadcastKey
    {
        element_t key_element;
        element_init_GT(key_element, pubKey.pairing);
        element_pow_zn(key_element, pubKey.v, k);

        // serialize to bytes and do a SHA
        int generated_key_length = element_length_in_bytes(key_element);
        unsigned char* key_element_bytes = (unsigned char*) malloc(generated_key_length);
        element_to_bytes(key_element_bytes, key_element);
        sgx_sha256(key_element_bytes, generated_key_length, *bKey);
        free(key_element_bytes);
    }

    element_init_G1(cipher->c1, pubKey.pairing);
    element_init_G1(cipher->c2, pubKey.pairing);
    element_init_G1(cipher->h_pow_product_gamma_hash, pubKey.pairing);
    element_set(cipher->c1, c1);
    element_set(cipher->c2, c2);
    element_set(cipher->h_pow_product_gamma_hash, c3);

    element_clear(k);
    element_clear(c1);
    element_clear(c2);
    element_clear(hash);
    element_clear(product);

    return 0;
}

// should have a correponding theorem in the paper.
int add_user_sgx_safe(ShortPublicKey spk, Ciphertext *cipher, MasterSecretKey msk, char* id)
{
    element_t hash;
    element_init_Zr(hash, spk.pairing);
    element_from_hash(hash, id, strlen(id));

    element_add(hash, hash, msk.gamma);
    element_pow_zn(cipher->c2, cipher->c2, hash);
    element_pow_zn(cipher->h_pow_product_gamma_hash, cipher->h_pow_product_gamma_hash, hash);

    element_clear(hash);
    return 0;
}

// should have a corresponding theorem in the paper
int rekey_sgx_safe(BroadcastKey* bKey, Ciphertext *cipher, ShortPublicKey spk, MasterSecretKey msk)
{
    // generate a new k
    element_t k;
    {
        element_init_Zr(k, spk.pairing);
        element_random(k);
    }

    // compute new Ciphertext elements
    {
        // c1
        element_pow_zn(cipher->c1, spk.w, k);
        element_invert(cipher->c1, cipher->c1);

        // c2
        element_pow_zn(cipher->c2, cipher->h_pow_product_gamma_hash, k);
    }

    // compute new boradcast key K
    {
        element_t key_element;
        element_init_GT(key_element, spk.pairing);
        element_pow_zn(key_element, spk.v, k);

        // serialize to bytes and do a SHA
        int generated_key_length = element_length_in_bytes(key_element);
        unsigned char* key_element_bytes = (unsigned char*) malloc(generated_key_length);
        element_to_bytes(key_element_bytes, key_element);
        sgx_sha256(key_element_bytes, generated_key_length, *bKey);
        free(key_element_bytes);
    }

    element_clear(k);
    return 0;
}

// theorem, see the blue paper for it
int remove_user_sgx_safe(
    BroadcastKey* bKey, Ciphertext *cipher,
    char* id,
    ShortPublicKey spk, MasterSecretKey msk)
{
    // generate a new k
    element_t k;
    {
        element_init_Zr(k, spk.pairing);
        element_random(k);
    }

    // compute new Ciphertext elements
    {
        // c1
        element_pow_zn(cipher->c1, spk.w, k);
        element_invert(cipher->c1, cipher->c1);

        //  h_pow_product_gamma_hash ^ 1/(gamma + hash)
        element_t hash;
        element_init_Zr(hash, spk.pairing);
        element_from_hash(hash, id, strlen(id));
        element_add(hash, hash, msk.gamma);
        element_invert(hash, hash);
        element_pow_zn(cipher->h_pow_product_gamma_hash, cipher->h_pow_product_gamma_hash, hash);

        // c2
        element_pow_zn(cipher->c2, cipher->h_pow_product_gamma_hash, k);
    }

    // compute new boradcast key K
    {
        element_t key_element;
        element_init_GT(key_element, spk.pairing);
        element_pow_zn(key_element, spk.v, k);

        // serialize to bytes and do a SHA
        int generated_key_length = element_length_in_bytes(key_element);
        unsigned char* key_element_bytes = (unsigned char*) malloc(generated_key_length);
        element_to_bytes(key_element_bytes, key_element);
        sgx_sha256(key_element_bytes, generated_key_length, *bKey);
        free(key_element_bytes);
    }

    element_clear(k);
    return 0;
}

int decrypt_sgx_safe(BroadcastKey* bKey, Ciphertext cipher,
    ShortPublicKey pubKey, MasterSecretKey msk,
    char idSet[][MAX_STRING_LENGTH], int idCount)
{
    element_t e_1, e_2;
    element_t product, hash;

    element_init_GT(e_1, pubKey.pairing);
    element_init_GT(e_2, pubKey.pairing);

    // compute the exponent
    {
        element_init_Zr(product, pubKey.pairing);
        element_set1(product);
        for (int i = 0; i < idCount; i++)
        {
            // compute hash
            element_init_Zr(hash, pubKey.pairing);
            element_from_hash(hash, idSet[i], strlen(idSet[i]));

            // sum hash with gamma and multiply into product
            element_add(hash, msk.gamma, hash);
            element_mul(product, product, hash);
        }

        element_sub(product, product, msk.gamma);
        element_invert(product, product);
    }

    // compute the pairings
    {
        element_pairing(e_1, cipher.c1, pubKey.h);
        element_pairing(e_2, msk.g, cipher.c2);
        element_mul(e_1, e_1, e_2);
    }

    // compute key
    {
        element_pow_zn(e_1, e_1, product);

        // serialize to bytes and do a SHA
        int generated_key_length = element_length_in_bytes(e_1);
        unsigned char* key_element_bytes = (unsigned char*) malloc(generated_key_length);
        element_to_bytes(key_element_bytes, e_1);
        sgx_sha256(key_element_bytes, generated_key_length, *bKey);
        free(key_element_bytes);
    }

    // clean-up
    {
        element_clear(e_1);
        element_clear(e_2);
        element_clear(product);
        element_clear(hash);
    }
}

int decrypt_with_key_sgx_safe(BroadcastKey* bKey, Ciphertext cipher,
    ShortPublicKey pubKey, MasterSecretKey msk, UserPrivateKey ikey,
    char* id, char idSet[][MAX_STRING_LENGTH], int idCount)
{
    element_t e_1, e_2;
    element_t sub_uni_exp;
    element_t hash;
    element_t p_hash, p_gamma_hash, p_term;
    element_t h_exp;
    element_t e1_hp;

    element_init_GT(e_1, pubKey.pairing);
    element_init_GT(e_2, pubKey.pairing);
    element_init_Zr(sub_uni_exp, pubKey.pairing);
    element_init_Zr(h_exp, pubKey.pairing);
    element_init_G2(e1_hp, pubKey.pairing);

    // compute the p exponent used by the first pairing
    {
        element_init_Zr(p_hash, pubKey.pairing);
        element_init_Zr(p_gamma_hash, pubKey.pairing);
        element_init_Zr(p_term, pubKey.pairing);
        element_set1(p_hash);
        element_set1(p_gamma_hash);
        for (int i = 0; i < idCount; i++)
        {
            // exclude the current user
            if (strcmp(id, idSet[i]) != 0)
            {
                // compute hash
                element_init_Zr(hash, pubKey.pairing);
                element_from_hash(hash, idSet[i], strlen(idSet[i]));

                // include hash in products
                element_mul(p_hash, p_hash, hash);
                element_add(p_term, hash, msk.gamma);
                element_mul(p_gamma_hash, p_gamma_hash, p_term);
            }
        }

        // multiply 1/gamma with (p_gamma_hash - p_hash)
        element_sub(p_gamma_hash, p_gamma_hash, p_hash);
        element_set(h_exp, msk.gamma);
        element_invert(h_exp, h_exp);
        element_mul(h_exp, h_exp, p_gamma_hash);
        element_pow_zn(e1_hp, pubKey.h, h_exp);
    }

    // compute the product of the two pairings
    {
        element_pairing(e_1, cipher.c1, e1_hp);
        element_pairing(e_2, ikey, cipher.c2);
        element_mul(e_1, e_1, e_2);
    }

    // finally compute key, serialize to bytes and SHA
    {
        element_set(sub_uni_exp, p_hash);
        element_invert(sub_uni_exp, sub_uni_exp);
        element_pow_zn(e_1, e_1, sub_uni_exp);

        // serialize to bytes and do a SHA
        int generated_key_length = element_length_in_bytes(e_1);
        unsigned char* key_element_bytes = (unsigned char*) malloc(generated_key_length);
        element_to_bytes(key_element_bytes, e_1);
        sgx_sha256(key_element_bytes, generated_key_length, *bKey);
        free(key_element_bytes);
    }

    // clean up
    element_clear(e_1);
    element_clear(e_2);
    element_clear(sub_uni_exp);
    element_clear(hash);
    element_clear(p_hash);
    element_clear(p_gamma_hash);
    element_clear(p_term);
    return 0;
}


