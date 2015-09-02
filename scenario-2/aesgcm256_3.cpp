//
// Created by ghunt on 8/31/15.
//

#include "aesgcm256_2.hpp"
#include "CryptoError.hpp"
#include "openssl/evp.h"
#include "openssl/err.h"

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

std::string lastOpenSSLError()
{
    unsigned long error = ERR_peek_error();
    char errorString[1024];
    if (error != 0) {
        std::string prefix(": ");
        strncpy(errorString, prefix.c_str(), prefix.length());
        ERR_error_string_n(error, errorString + 2, sizeof(errorString) - 2);
    } else {
        errorString[0] = 0;
    }
    return std::string(errorString);
}

const size_t TAG_LEN(16);
const size_t IV_LEN(12);

void basicEncryptAesGcm256_3(const std::vector<unsigned char>& key,
                             const std::vector<unsigned char>& iv,
                             const std::vector<unsigned char>& plainText,
                             std::vector<unsigned char>& cipherText,
                             std::vector<unsigned char>& tag)
{
    /**
     * Using EVP_CIPHER_CTX_new() and EVP_CIPHER_CTX_free() are deprecated
     * because the free function would leave cryptographic items in memory.
     */
    EVP_CIPHER_CTX context;
    EVP_CIPHER_CTX_init(&context);

    if (0 == EVP_EncryptInit_ex(&context, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        THROW_CRYPTO_ERROR(lastOpenSSLError());
    }
    if (0 == EVP_EncryptInit_ex(&context, NULL, NULL, &key[0], &iv[0])) {
        THROW_CRYPTO_ERROR(lastOpenSSLError());
    }

    int plainTextLen{static_cast<int>(plainText.size())};
    cipherText.clear();
    cipherText.resize(plainTextLen);
    int cipherTextLen{0};

    if (0 == EVP_EncryptUpdate(&context, &cipherText[0], &cipherTextLen, &plainText[0], plainTextLen)) {
        THROW_CRYPTO_ERROR(lastOpenSSLError());
    }
    if (0 == EVP_EncryptFinal_ex(&context, &cipherText[cipherTextLen], &cipherTextLen)) {
        THROW_CRYPTO_ERROR(lastOpenSSLError());
    }
    if (0 ==  EVP_CIPHER_CTX_ctrl(&context, EVP_CTRL_GCM_GET_TAG, TAG_LEN, &tag[0])) {
        THROW_CRYPTO_ERROR(lastOpenSSLError());
    }
    if (0 == EVP_CIPHER_CTX_cleanup(&context)) {
        THROW_CRYPTO_ERROR(lastOpenSSLError());
    }
}

void basicDecryptAesGcm256_3(const std::vector<unsigned char>& key,
                             const std::vector<unsigned char>& tag,
                             const std::vector<unsigned char>& iv,
                             const std::vector<unsigned char>& cipherText,
                             std::vector<unsigned char>& plainText)
{
    /**
     * Using EVP_CIPHER_CTX_new() and EVP_CIPHER_CTX_free() are deprecated
     * because the free function would leave cryptographic items in memory.
     */
    EVP_CIPHER_CTX context;
    EVP_CIPHER_CTX_init(&context);

    if (0 == EVP_DecryptInit_ex(&context, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        THROW_CRYPTO_ERROR(lastOpenSSLError());
    }

    if (0 == EVP_DecryptInit_ex(&context, NULL, NULL, &key[0], &iv[0])) {
        THROW_CRYPTO_ERROR(lastOpenSSLError());
    }

    int workingLen{0};
    if (0 == EVP_DecryptUpdate(&context, &plainText[0], &workingLen, &cipherText[0], cipherText.size())) {
        THROW_CRYPTO_ERROR(lastOpenSSLError());
    }

    int plainTextLen{workingLen};
    std::vector<unsigned char> tagCopy(tag);
    if (0 == EVP_CIPHER_CTX_ctrl(&context, EVP_CTRL_GCM_SET_TAG, TAG_LEN, &tagCopy[0])) {
        THROW_CRYPTO_ERROR(lastOpenSSLError());
    }
    if (0 == EVP_DecryptFinal_ex(&context, &plainText[workingLen], &workingLen)) {
        THROW_CRYPTO_ERROR(lastOpenSSLError());
    }
    plainTextLen += workingLen;
    if (0 == EVP_CIPHER_CTX_cleanup(&context)) {
        THROW_CRYPTO_ERROR(lastOpenSSLError());
    }
}

int cipherTextLength(const std::string& combinedElements)
{
    return combinedElements.size() - (TAG_LEN + IV_LEN); // tagLen + ivLen == 28
}

/**
 * Utility function that assembles the resulting components of encyption using AES-GCM-256
 * into a std::string that can be used for
 */
void composeEncryptedMessage(const std::string& tag,
                             const std::string& iv,
                             const std::string& cipherText,
                             std::string& encryptedMessage)
{
    encryptedMessage.clear();
    encryptedMessage.reserve(TAG_LEN + IV_LEN + cipherText.size());
    std::copy(tag.begin(), tag.end(), std::back_inserter(encryptedMessage));
    std::copy(iv.begin(), iv.end(), std::back_inserter(encryptedMessage));
    std::copy(cipherText.begin(), cipherText.end(), std::back_inserter(encryptedMessage));
}

void parseEncryptedMessage(const std::string& encryptedMessage,
                           std::string& tag,
                           std::string& iv,
                           std::string& cipherText)
{
    tag.clear();
    iv.clear();
    cipherText.clear();
    tag.assign(encryptedMessage.begin(), encryptedMessage.begin() + TAG_LEN);
    iv.assign(encryptedMessage.begin() + TAG_LEN, encryptedMessage.begin() + TAG_LEN + IV_LEN);
    cipherText.assign(encryptedMessage.begin() + TAG_LEN + IV_LEN, encryptedMessage.end());
}

} // namespace null


namespace secp
{

void authAes256GcmEncrypt_3(const std::string& key,
                            const std::string& iv,
                            const std::string& plainText,
                            std::string& tag,
                            std::string& cipherText)
{
    std::vector<unsigned char> vKey{key.begin(), key.end()};
    std::vector<unsigned char> vIv{iv.begin(), iv.end()};
    std::vector<unsigned char> vPt{plainText.begin(), plainText.end()};
    std::vector<unsigned char> vTag(TAG_LEN);
    std::vector<unsigned char> vCt(vPt.size());

    basicEncryptAesGcm256_3(vKey, vIv, vPt, vCt, vTag);
    tag.assign(vTag.begin(), vTag.end());
    cipherText.assign(vCt.begin(), vCt.end());
}

void authAes256GcmDecrypt_3(const std::string& key,
                            const std::string& tag,
                            const std::string& iv,
                            const std::string& cipherText,
                            std::string& plainText)
{
    std::vector<unsigned char> vKey(key.begin(), key.end());
    std::vector<unsigned char> vTag(tag.begin(), tag.end());
    std::vector<unsigned char> vIv(iv.begin(), iv.end());
    std::vector<unsigned char> vCt(cipherText.begin(), cipherText.end());

    int ctextLen{static_cast<int>(cipherText.size())};
    int ptextLen{ctextLen};
    std::vector<unsigned char> vPt(ptextLen);

    basicDecryptAesGcm256_3(vKey, vTag, vIv, vCt, vPt);
    plainText.assign(vPt.begin(), vPt.end());
}

} // namespace secp