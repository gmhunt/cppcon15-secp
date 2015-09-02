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


void authAes256GcmEncrypt_1(const std::string& key,
                            const std::string& iv,
                            const std::string& ptext,
                            std::string& tag,
                            std::string& cipherText)
{
    std::vector<unsigned char> vKey(key.begin(), key.end());
    std::vector<unsigned char> vIv(iv.begin(), iv.end());
    std::vector<unsigned char> vPT(ptext.begin(), ptext.end());
    std::vector<unsigned char> vTag(16);
    std::vector<unsigned char> vCT(vPT.size());

    int ctextLen(0);
    basicEncryptAesGcm256_1(&vKey[0], &vIv[0], &vPT[0], vPT.size(), &vCT[0], ctextLen, &vTag[0]);
    tag.assign(vTag.begin(), vTag.end());
    cipherText.assign(vCT.begin(), vCT.end());
}

void authAes256GcmDecrypt_1(const std::string& key,
                            const std::string& tag,
                            const std::string& iv,
                            const std::string& cipherText,
                            std::string& plainText)
{
    std::vector<unsigned char> vKey(key.begin(), key.end());
    std::vector<unsigned char> vTag(tag.begin(), tag.end());
    std::vector<unsigned char> vIv(iv.begin(), iv.end());
    std::vector<unsigned char> vCt(cipherText.begin(), cipherText.end());

    int ctextLen = (int)cipherText.size();
    int ptextLen(ctextLen);
    std::vector<unsigned char> vPt(ptextLen);

    basicDecryptAesGcm256_1(&vKey[0], &vTag[0], &vIv[0], &vCt[0], ctextLen, &vPt[0], ptextLen);
    plainText.assign(vPt.begin(), vPt.end());
}

} // namespace secp