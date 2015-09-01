//
// Created by ghunt on 8/31/15.
//

//#include "aesgcm256-1.h"

#include "openssl/aes.h"
#include "openssl/evp.h"
#include "openssl/rand.h"

#include <string>
#include <vector>

namespace secp
{

/**
 * Method for encrypting data using AES-GCM-256 and transporting as bytes in a message
 *
 * 1. A shared secret or key of 256-bits must be available for both doing the encryption and decryption.
 *    NOTE: Key is never sent with the encrypted message.
 *
 * 2. All encryption and decryption required an initialization vector of 16-bytes (96-bits).  The iv doesn't
 *    have to be random for this algorithm but cannot be used more than once with the same key.
 * 3. Encryption produces a 16 bytes tag used for tampering detection.
 * 4. All three output elements from encryption must be concatenated together in a std::string used
 *    to set a string field in a Google protobuf message.
 *
 *    tag (16-bytes) + iv (12-bytes) + cipherText (variable)
 *
 * 5. Decryption function takes in the std::string and parses it into the tag, iv and cipher text
 *    components.
 *
 */

/**
 *  Encryption function using OpenSSL
 *
 *  Algorithm AES-GCM-256
 *
 *  @param key              IN  encryption key: pointer to unsigned char array. Must be 256-bits or longer.
 *  @param iv               IN  initialization vector: pointer to unsigned char array. Must be 96-bits
 *                              in length and never, ever reused with the same key.
 *  @param plaintText       IN  pointer to unsigned char array of text that will be encrypted.
 *  @param plainTextLen     IN  length of plainText
 *  @param cipherText       OUT pointer to preallocated unsigned char array with a length at least the same
 *                              as plainTextLen.
 *  @param cipherTextLen    OUT reference to unsigned int for the finished length of cipherText.
 *  @param tag              OUT pointer to a preallocated unsigned char array of 16 bytes
 *
 *  @return                 SUCCESS == 1
 *                          FAILURE == 0
 */
int basicEncryptAesGcm256_1(const unsigned char *key,
                            const unsigned char *iv,
                            const unsigned char *plainText,
                            int plainTextLen,
                            unsigned char *cipherText,
                            int &cipherTextLen,
                            unsigned char *tag)
{
    int rc;
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
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
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
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
                                                const int tagLen,
                                                const unsigned char *iv,
                                                const int ivLen,
                                                const unsigned char *cipherText,
                                                const int cipherTextLen)
{

    std::vector<unsigned char> v(tagLen + ivLen + cipherTextLen);
    memcpy((void *) &v[0], (void *) tag, (size_t) tagLen);
    memcpy((void *) &v[tagLen], (void *) iv, (size_t) ivLen);
    memcpy((void *) &v[tagLen + ivLen], (void *) cipherText, (size_t) cipherTextLen);
    std::string result(v.begin(), v.end());
    return result;
}

int cipherTextLength(const std::string& combinedElements)
{
    return combinedElements.size() - 28; // tagLen + ivLen == 28
}


std::string authAes256GcmEncrypt_1(const std::string &key,
                                   const std::string &iv,
                                   const std::string &ptext)
{
    std::vector<unsigned char> vKey(key.begin(), key.end());
    std::vector<unsigned char> vIv(iv.begin(), iv.end());
    std::vector<unsigned char> vPT(ptext.begin(), ptext.end());
    std::vector<unsigned char> vTag(16);
    std::vector<unsigned char> vCT(vPT.size());

    int ctextLen(0);
    basicEncryptAesGcm256_1(&vKey[0], &vIv[0], &vPT[0], vPT.size(), &vCT[0], ctextLen, &vTag[0]);
    return combineAesGcm256EncryptedElements_1(&vTag[0], vTag.size(), &vIv[0], vIv.size(), &vCT[0], vCT.size());
}


std::string authAes256GcmDecrypt_1(const std::string& key,
                                   const std::string& combinedElements)
{
    std::vector<unsigned char> vKey(key.begin(), key.end());

    int ctextLen = cipherTextLength(combinedElements);
    int tagLen(16);
    int ivLen(12);
    std::vector<unsigned char> vTag(combinedElements.begin(), combinedElements.begin() + tagLen);
    std::vector<unsigned char> vIv(combinedElements.begin() + tagLen, combinedElements.begin() + ivLen);
    std::vector<unsigned char> vCt(combinedElements.begin() + tagLen + ivLen, combinedElements.end());

    int ptextLen(ctextLen);
    std::vector<unsigned char> vPt(ptextLen);

    basicDecryptAesGcm256_1(&vKey[0], &vTag[0], &vIv[0], &vCt[0], ctextLen, &vPt[0], ptextLen);

    std::string plainText(vPt.begin(), vPt.end());
    return plainText;
}

} // namespace secp