//
// Created by Gwendolyn Hunt on 9/6/15.
//

#ifndef SECP_DEMOWRAPPER_H
#define SECP_DEMOWRAPPER_H

#include "aesgcm256_1.hpp"
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
    virtual void encrypt(const std::vector<unsigned char> &key,
                         const std::vector<unsigned char> &iv,
                         const std::vector<unsigned char> &plainText,
                         std::vector<unsigned char> &tag,
                         std::vector<unsigned char> &cipherText) = 0;

    virtual void decrypt(const std::vector<unsigned char> &key,
                         const std::vector<unsigned char> &tag,
                         const std::vector<unsigned char> &iv,
                         const std::vector<unsigned char> &cipherText,
                         std::vector<unsigned char> &plainText) = 0;
};

class Demo1Tester : public DemoWrapper
{
public:
    void encrypt(const std::vector<unsigned char> &key,
                 const std::vector<unsigned char> &iv,
                 const std::vector<unsigned char> &plainText,
                 std::vector<unsigned char> &tag,
                 std::vector<unsigned char> &cipherText)
    {
        int ptextLen = (int)plainText.size();
        int ctextLen(ptextLen);

        cipherText.clear();
        cipherText.resize(ptextLen);

        encryptAesGcm256_1(&key[0], &iv[0], &plainText[0], plainText.size(), &cipherText[0], ctextLen, &tag[0]);
    }

    void decrypt(const std::vector<unsigned char> &key,
                 const std::vector<unsigned char> &tag,
                 const std::vector<unsigned char> &iv,
                 const std::vector<unsigned char> &cipherText,
                 std::vector<unsigned char> &plainText)
    {
        int ctextLen = (int)cipherText.size();
        int ptextLen(ctextLen);

        plainText.clear();
        plainText.resize(ptextLen);

        decryptAesGcm256_1(&key[0], &tag[0], &iv[0], &cipherText[0], ctextLen, &plainText[0], ptextLen);
    };
};

class Demo2Tester : public DemoWrapper
{
public:
    void encrypt(const std::vector<unsigned char> &key,
                 const std::vector<unsigned char> &iv,
                 const std::vector<unsigned char> &plainText,
                 std::vector<unsigned char> &tag,
                 std::vector<unsigned char> &cipherText)
    {
        secp::authAes256GcmEncrypt_2(key, iv, plainText, tag, cipherText);
    }

    void decrypt(const std::vector<unsigned char> &key,
                 const std::vector<unsigned char> &tag,
                 const std::vector<unsigned char> &iv,
                 const std::vector<unsigned char> &cipherText,
                 std::vector<unsigned char> &plainText)
    {
        secp::authAes256GcmDecrypt_2(key, tag, iv, cipherText, plainText);
    };
};

class Demo3Tester : public DemoWrapper
{
public:
    void encrypt(const std::vector<unsigned char> &key,
                 const std::vector<unsigned char> &iv,
                 const std::vector<unsigned char> &plainText,
                 std::vector<unsigned char> &tag,
                 std::vector<unsigned char> &cipherText)
    {
        secp::authAes256GcmEncrypt_3(key, iv, plainText, tag, cipherText);
    }

    void decrypt(const std::vector<unsigned char> &key,
                 const std::vector<unsigned char> &tag,
                 const std::vector<unsigned char> &iv,
                 const std::vector<unsigned char> &cipherText,
                 std::vector<unsigned char> &plainText)
    {
        secp::authAes256GcmDecrypt_3(key, tag, iv, cipherText, plainText);
    };
};

class Demo4Tester : public DemoWrapper
{
public:
    void encrypt(const std::vector<unsigned char> &key,
                 const std::vector<unsigned char> &iv,
                 const std::vector<unsigned char> &plainText,
                 std::vector<unsigned char> &tag,
                 std::vector<unsigned char> &cipherText)
    {
        secp::authAes256GcmEncrypt_4(key, iv, plainText, tag, cipherText);
    }

    void decrypt(const std::vector<unsigned char> &key,
                 const std::vector<unsigned char> &tag,
                 const std::vector<unsigned char> &iv,
                 const std::vector<unsigned char> &cipherText,
                 std::vector<unsigned char> &plainText)
    {
        secp::authAes256GcmDecrypt_4(key, tag, iv, cipherText, plainText);
    };
};

} // namespace secp

#endif //SECP_DEMOWRAPPER_H
