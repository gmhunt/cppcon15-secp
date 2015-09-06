//
// Created by ghunt on 8/31/15.
//

#include "aesgcm256_1.hpp"
#include "openssl/evp.h"
#include <string.h>

namespace secp
{

int encryptAesGcm256_1(const unsigned char *key,
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

int decryptAesGcm256_1(const unsigned char *key,
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

} // namespace secp