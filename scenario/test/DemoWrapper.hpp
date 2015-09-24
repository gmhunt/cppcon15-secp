//
// Created by Gwendolyn Hunt on 9/6/15.
//

#ifndef SECP_DEMOWRAPPER_H
#define SECP_DEMOWRAPPER_H

#include "aesgcm256_2.hpp"
#include "aesgcm256_3.hpp"
#include "aesgcm256_4.hpp"
#include <string>
#include <vector>

/**
 * The following classes wraps the various encrypt/decrypt functions.
 * This allows us to test each variation using common test code.
 */
namespace secp
{

class DemoWrapper
{
public:
    virtual void encrypt(const std::vector<unsigned char>& key,
                         const std::vector<unsigned char>& iv,
                         const std::vector<unsigned char>& plainText,
                         std::vector<unsigned char>& tag,
                         std::vector<unsigned char>& cipherText) = 0;

    virtual void decrypt(const std::vector<unsigned char>& key,
                         const std::vector<unsigned char>& tag,
                         const std::vector<unsigned char>& iv,
                         const std::vector<unsigned char>& cipherText,
                         std::vector<unsigned char>& plainText) = 0;
};

class Demo2Tester : public DemoWrapper
{
public:
    void encrypt(const std::vector<unsigned char>& key,
                 const std::vector<unsigned char>& iv,
                 const std::vector<unsigned char>& plainText,
                 std::vector<unsigned char>& tag,
                 std::vector<unsigned char>& cipherText)
    {
        authAes256GcmEncrypt_2(key, iv, plainText, tag, cipherText);
    }

    void decrypt(const std::vector<unsigned char>& key,
                 const std::vector<unsigned char>& tag,
                 const std::vector<unsigned char>& iv,
                 const std::vector<unsigned char>& cipherText,
                 std::vector<unsigned char>& plainText)
    {
        authAes256GcmDecrypt_2(key, tag, iv, cipherText, plainText);
    };
};

class Demo3Tester : public DemoWrapper
{
public:
    void encrypt(const std::vector<unsigned char>& key,
                 const std::vector<unsigned char>& iv,
                 const std::vector<unsigned char>& plainText,
                 std::vector<unsigned char>& tag,
                 std::vector<unsigned char>& cipherText)
    {
        authAes256GcmEncrypt_3(key, iv, plainText, tag, cipherText);
    }

    void decrypt(const std::vector<unsigned char>& key,
                 const std::vector<unsigned char>& tag,
                 const std::vector<unsigned char>& iv,
                 const std::vector<unsigned char>& cipherText,
                 std::vector<unsigned char>& plainText)
    {
        authAes256GcmDecrypt_3(key, tag, iv, cipherText, plainText);
    };
};

class Demo4Tester : public DemoWrapper
{
public:
    void encrypt(const std::vector<unsigned char>& key,
                 const std::vector<unsigned char>& iv,
                 const std::vector<unsigned char>& plainText,
                 std::vector<unsigned char>& tag,
                 std::vector<unsigned char>& cipherText)
    {
        authAes256GcmEncrypt_4(key, iv, plainText, tag, cipherText);
    }

    void decrypt(const std::vector<unsigned char>& key,
                 const std::vector<unsigned char>& tag,
                 const std::vector<unsigned char>& iv,
                 const std::vector<unsigned char>& cipherText,
                 std::vector<unsigned char>& plainText)
    {
        authAes256GcmDecrypt_4(key, tag, iv, cipherText, plainText);
    };
};

} // namespace secp

#endif //SECP_DEMOWRAPPER_H
