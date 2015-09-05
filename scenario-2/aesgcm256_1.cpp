//
// Created by ghunt on 8/31/15.
//

#include "aesgcm256_1.hpp"
#include "openssl/evp.h"


namespace secp
{

int basicEncryptAesGcm256_1(const unsigned char *key,
                            const unsigned char *iv,
                            const unsigned char *plainText,
                            int plainTextLen,
                            unsigned char *cipherText,
                            int &cipherTextLen,
                            unsigned char *tag)
{
    int rc;
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(context, NULL, NULL, key, iv);
    EVP_EncryptUpdate(context, cipherText, &cipherTextLen, plainText, plainTextLen);
    // Return 1 success, 0 failed
    rc = EVP_EncryptFinal_ex(context, cipherText + cipherTextLen, &cipherTextLen);
    EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(context);
    return rc;
}

int basicDecryptAesGcm256_1(const unsigned char *key,
                            const unsigned char *tag,
                            const unsigned char *iv,
                            const unsigned char *cipherText,
                            const int cipherTextLen,
                            unsigned char *plainText,
                            int &plainTextLen)
{
    int rc;
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(context, NULL, NULL, key, iv);

    int workingLen(0);
    EVP_DecryptUpdate(context, plainText, &workingLen, cipherText, cipherTextLen);
    plainTextLen =  workingLen;

    std::vector<unsigned char> tagCopy(16);
    memcpy((void*)&tagCopy[0], (void*)tag, 16);
    EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, 16, &tagCopy[0]);

    // Return 1 success, 0 failed
    rc = EVP_DecryptFinal_ex(context, plainText + workingLen, &workingLen);
    plainTextLen += workingLen;
    EVP_CIPHER_CTX_free(context);
    return rc;
}


/**
 * Utility function that assembles the resulting components of encyption using AES-GCM-256
 * into a std::string that can be used for
 */
std::string combineAesGcm256EncryptedElements_1(const unsigned char *tag,
                                                const unsigned char *iv,
                                                const unsigned char *cipherText,
                                                const int cipherTextLen)
{
    int tagLen(16);
    int ivLen(12);
    std::vector<unsigned char> v(tagLen + ivLen + cipherTextLen);
    memcpy((void *) &v[0], (void *) tag, (size_t) tagLen);
    memcpy((void *) &v[tagLen], (void *) iv, (size_t) ivLen);
    memcpy((void *) &v[tagLen + ivLen], (void *) cipherText, (size_t) cipherTextLen);
    std::string result(v.begin(), v.end());
    return result;
}

int cipherTextLength(const std::string& combinedElements)
{
    return combinedElements.size() - (16 + 12); // tagLen + ivLen == 28
}


void authAes256GcmEncrypt_1(const std::vector<unsigned char>& key,
                            const std::vector<unsigned char>& iv,
                            const std::vector<unsigned char>& plainText,
                            std::vector<unsigned char>& tag,
                            std::vector<unsigned char>& cipherText)
{
    int ptextLen = (int)plainText.size();
    int ctextLen(ptextLen);

    cipherText.clear();
    cipherText.resize(ptextLen);

    basicEncryptAesGcm256_1(&key[0], &iv[0], &plainText[0], plainText.size(), &cipherText[0], ctextLen, &tag[0]);
}

void authAes256GcmDecrypt_1(const std::vector<unsigned char>& key,
                            const std::vector<unsigned char>& tag,
                            const std::vector<unsigned char>& iv,
                            const std::vector<unsigned char>& cipherText,
                            std::vector<unsigned char>& plainText)
{
    int ctextLen = (int)cipherText.size();
    int ptextLen(ctextLen);

    plainText.clear();
    plainText.resize(ptextLen);

    basicDecryptAesGcm256_1(&key[0], &tag[0], &iv[0], &cipherText[0], ctextLen, &plainText[0], ptextLen);
}

} // namespace secp