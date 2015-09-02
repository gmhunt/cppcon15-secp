//
// Created by ghunt on 8/31/15.
//

#include "aesgcm256_2.hpp"

#include "openssl/aes.h"
#include "openssl/evp.h"
#include "openssl/rand.h"

/**
 * Method for encrypting data using AES-GCM-256 and transporting as bytes in a message
 *
 * 1. A shared secret or key of 256-bits must be available for both doing the encryption and decryption.
 *
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


namespace
{
const size_t TAG_LEN(16);
const size_t IV_LEN(12);

int basicEncryptAesGcm256_2(const unsigned char *key,
                            const unsigned char *iv,
                            const unsigned char *plainText,
                            int plainTextLen,
                            unsigned char *cipherText,
                            int &cipherTextLen,
                            unsigned char *tag)
{
    // Non-zero equals success, 0 equals failure
    int rc(0);

    /**
     * Using EVP_CIPHER_CTX_new() and EVP_CIPHER_CTX_free() are deprecated
     * because the free function would leave cryptographic items in memory.
     */
    EVP_CIPHER_CTX context;
    EVP_CIPHER_CTX_init(&context);

    rc = EVP_EncryptInit_ex(&context, EVP_aes_256_gcm(), NULL, NULL, NULL);
    if (rc == 0) {
        return rc;
    }
    rc = EVP_EncryptInit_ex(&context, NULL, NULL, key, iv);
    if (rc == 0) {
        return rc;
    }
    rc = EVP_EncryptUpdate(&context, cipherText, &cipherTextLen, plainText, plainTextLen);
    if (rc == 0) {
        return rc;
    }
    // Return 1 success, 0 failed
    rc = EVP_EncryptFinal_ex(&context, cipherText + cipherTextLen, &cipherTextLen);
    if (rc == 0) {
        return rc;
    }
    rc = EVP_CIPHER_CTX_ctrl(&context, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
    if (rc == 0) {
        return rc;
    }

    EVP_CIPHER_CTX_cleanup(&context);
    if (rc == 0) {
        return rc;
    }
    rc = 1;
    return rc;
}

int basicDecryptAesGcm256_2(const unsigned char *key,
                            const unsigned char *tag,
                            const unsigned char *iv,
                            const unsigned char *cipherText,
                            const int cipherTextLen,
                            unsigned char *plainText,
                            int &plainTextLen)
{
    int rc;
    /**
     * Using EVP_CIPHER_CTX_new() and EVP_CIPHER_CTX_free() are deprecated
     * because the free function would leave cryptographic items in memory.
     */
    EVP_CIPHER_CTX context;
    EVP_CIPHER_CTX_init(&context);

    rc = EVP_DecryptInit_ex(&context, EVP_aes_256_gcm(), NULL, NULL, NULL);
    if (rc == 0) {
        return rc;
    }
    rc = EVP_DecryptInit_ex(&context, NULL, NULL, key, iv);
    if (rc == 0) {
        return rc;
    }

    int workingLen(0);
    rc = EVP_DecryptUpdate(&context, plainText, &workingLen, cipherText, cipherTextLen);
    if (rc == 0) {
        return rc;
    }

    plainTextLen =  workingLen;
    std::vector<unsigned char> tagCopy(TAG_LEN);
    memcpy((void*)&tagCopy[0], (void*)tag, TAG_LEN);
    rc = EVP_CIPHER_CTX_ctrl(&context, EVP_CTRL_GCM_SET_TAG, TAG_LEN, &tagCopy[0]);
    if (rc == 0) {
        return rc;
    }

    // Return 1 success, 0 failed
    rc = EVP_DecryptFinal_ex(&context, plainText + workingLen, &workingLen);
    if (rc == 0) {
        return rc;
    }
    plainTextLen += workingLen;
    rc = EVP_CIPHER_CTX_cleanup(&context);
    if (rc == 0) {
        return rc;
    }
    rc = 1;
    return rc;
}


/**
 * Utility function that assembles the resulting components of encyption using AES-GCM-256
 * into a std::string that can be used for
 */
std::string combineAesGcm256EncryptedElements_2(const unsigned char *tag,
                                                const unsigned char *iv,
                                                const unsigned char *cipherText,
                                                const int cipherTextLen)
{
    size_t ctextLen = static_cast<size_t>(cipherTextLen);
    std::vector<unsigned char> vTag(tag, tag + TAG_LEN);
    std::vector<unsigned char> vIv(iv, iv + IV_LEN);
    std::vector<unsigned char> vCT(cipherText, cipherText + ctextLen);

    std::string result;
    result.reserve(TAG_LEN + IV_LEN + ctextLen);
    std::copy(vTag.begin(), vTag.end(), std::back_inserter(result));
    std::copy(vIv.begin(), vIv.end(), std::back_inserter(result));
    std::copy(vCT.begin(), vCT.end(), std::back_inserter(result));
    return result;
}

int cipherTextLength(const std::string& combinedElements)
{
    return combinedElements.size() - 28; // tagLen + ivLen == 28
}

} // namespace null


namespace secp
{


std::string authAes256GcmEncrypt_2(const std::string &key,
                                   const std::string &iv,
                                   const std::string &ptext)
{
    std::vector<unsigned char> vKey(key.begin(), key.end());
    std::vector<unsigned char> vIv(iv.begin(), iv.end());
    std::vector<unsigned char> vPT(ptext.begin(), ptext.end());
    std::vector<unsigned char> vTag(TAG_LEN);
    std::vector<unsigned char> vCT(vPT.size());

    int ctextLen(0);
    basicEncryptAesGcm256_2(&vKey[0], &vIv[0], &vPT[0], vPT.size(), &vCT[0], ctextLen, &vTag[0]);
    return combineAesGcm256EncryptedElements_2(&vTag[0], &vIv[0], &vCT[0], vCT.size());
}


std::string authAes256GcmDecrypt_2(const std::string& key,
                                   const std::string& combinedElements)
{
    std::vector<unsigned char> vKey(key.begin(), key.end());

    int ctextLen = cipherTextLength(combinedElements);
    int tagLen(TAG_LEN);
    int ivLen(IV_LEN);
    std::vector<unsigned char> vTag(combinedElements.begin(), combinedElements.begin() + tagLen);
    std::vector<unsigned char> vIv(combinedElements.begin() + tagLen, combinedElements.begin() + ivLen);
    std::vector<unsigned char> vCt(combinedElements.begin() + tagLen + ivLen, combinedElements.end());

    int ptextLen(ctextLen);
    std::vector<unsigned char> vPt(ptextLen);

    basicDecryptAesGcm256_2(&vKey[0], &vTag[0], &vIv[0], &vCt[0], ctextLen, &vPt[0], ptextLen);

    std::string plainText(vPt.begin(), vPt.end());
    return plainText;
}


} // namespace secp