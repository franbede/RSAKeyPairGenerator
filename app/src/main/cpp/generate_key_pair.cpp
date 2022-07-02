#define JNIIMPORT
#define JNIEXPORT  __attribute__ ((visibility ("default")))
#define JNICALL
#define LOG_TAG "Test"


#include <memory>
using std::unique_ptr;

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

#include <cassert>
#include <jni.h>
#include <android/log.h>
#include <cstdio>
#define ASSERT assert

using BN_ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
using RSA_ptr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
using EVP_KEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using BIO_FILE_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;

extern "C"
JNIEXPORT jobjectArray JNICALL
Java_eu_joober_rsakeypairgenerator_EncryptionUtils_generateRSAKeyPair(JNIEnv *env, jobject thiz) {
    int rc;
    char * public_key_text;
    char * private_key_text;
    jobjectArray returnPair = env->NewObjectArray(2, env->FindClass("java/lang/String"),jstring());

    RSA_ptr rsa(RSA_new(), ::RSA_free);
    BN_ptr bn(BN_new(), ::BN_free);
    BIO *bp_public = BIO_new(BIO_s_mem()), *bp_private = BIO_new(BIO_s_mem());;

//    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "[generate_key_pair.cpp] Setting BN_set_word...");
    rc = BN_set_word(bn.get(), RSA_F4);
            ASSERT(rc == 1);

    // Generate key
//    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "[generate_key_pair.cpp] Generating RSA keys...");
    rc = RSA_generate_key_ex(rsa.get(), 2048, bn.get(), nullptr);
            ASSERT(rc == 1);

    // Convert RSA to PKEY
//    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "[generate_key_pair.cpp] Converting to PKEY format...");
    EVP_KEY_ptr pkey(EVP_PKEY_new(), ::EVP_PKEY_free);
    rc = EVP_PKEY_set1_RSA(pkey.get(), rsa.get());
            ASSERT(rc == 1);

    // Write public key in PKCS PEM
//    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "[generate_key_pair.cpp] Writing public key...");
    rc = PEM_write_bio_PUBKEY(bp_public, pkey.get());
            ASSERT(rc == 1);
    BIO_get_mem_data(bp_public, &public_key_text);

    // Write private key in Traditional PEM
//    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "[generate_key_pair.cpp] Writing private key...");
    rc = PEM_write_bio_RSAPrivateKey(bp_private, rsa.get(), nullptr, nullptr, 0, nullptr, nullptr);
            ASSERT(rc == 1);
    BIO_get_mem_data(bp_private, &private_key_text);

    // 4. Return strings using jobjectArray
    env->SetObjectArrayElement(returnPair, 0, env->NewStringUTF(public_key_text));
    env->SetObjectArrayElement(returnPair, 1, env->NewStringUTF(private_key_text));
//    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "[generate_key_pair.cpp] Keys correctly generated...");
    delete public_key_text;
    delete private_key_text;
    return returnPair;
}