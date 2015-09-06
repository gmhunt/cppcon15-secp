//
// Created by ghunt on 8/31/15.
//

#include "aesgcm256_3.hpp"
#include "CryptoError.hpp"
#include "openssl/evp.h"
#include <sstream>
#include <string.h>
#include <limits>

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

std::string lastCryptoError()
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
const size_t KEY_LEN(32);

std::string lengthFormatError(const std::string& item, const size_t actualSize, const size_t wantedSize)
{
    std::stringstream ss;
    ss << "Length Error for '" << item << "' size: '" << actualSize << "' should be: '" << wantedSize << "'";
    return ss.str();
}



void basicEncryptAesGcm256_4(const std::vector<unsigned char>& key,
                             const std::vector<unsigned char>& iv,
                             const std::vector<unsigned char>& plainText,
                             std::vector<unsigned char>& cipherText,
                             std::vector<unsigned char>& tag)
{
    EVP_CIPHER_CTX context;
    EVP_CIPHER_CTX_init(&context);

    if (0 == EVP_EncryptInit_ex(&context, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        THROW_CRYPTO_ERROR(lastCryptoError());
    }
    if (0 == EVP_EncryptInit_ex(&context, NULL, NULL, &key[0], &iv[0])) {
        THROW_CRYPTO_ERROR(lastCryptoError());
    }
    /**
     * In the following statement we have a narrowing conversion to satisfy the type
     * required for the c API of size_t -> int. Since the caller of this function verifies that
     * the length of plainText does not exceed the max positive value of an int and this
     * function bring private to this compilation unit we are OK with narrowing
     * conversion.  We use an explicit cast to squelch the compile warning.
     */
    int plainTextLen{static_cast<int>(plainText.size())};
    cipherText.clear();

    /**
     * The next line without the cast would be a harmless widening conversion of an int to size_t.
     * We use an explicit static_cast<size_t> to silence the compile warning.
     */
    cipherText.resize(static_cast<size_t>(plainTextLen));
    int cipherTextLen{0};

    if (0 == EVP_EncryptUpdate(&context, &cipherText[0], &cipherTextLen, &plainText[0], plainTextLen)) {
        THROW_CRYPTO_ERROR(lastCryptoError());
    }

    /**
     * The next line without the cast would be a harmless widening conversion of an int to size_t.
     * We use an explicit static_cast<size_t> to silence the compile warning.
     */
    if (0 == EVP_EncryptFinal_ex(&context, &cipherText[static_cast<size_t>(cipherTextLen)], &cipherTextLen)) {
        THROW_CRYPTO_ERROR(lastCryptoError());
    }
    if (0 ==  EVP_CIPHER_CTX_ctrl(&context, EVP_CTRL_GCM_GET_TAG, TAG_LEN, &tag[0])) {
        THROW_CRYPTO_ERROR(lastCryptoError());
    }
    if (0 == EVP_CIPHER_CTX_cleanup(&context)) {
        THROW_CRYPTO_ERROR(lastCryptoError());
    }
}

void basicDecryptAesGcm256_4(const std::vector<unsigned char>& key,
                             const std::vector<unsigned char>& tag,
                             const std::vector<unsigned char>& iv,
                             const std::vector<unsigned char>& cipherText,
                             std::vector<unsigned char>& plainText)
{
    EVP_CIPHER_CTX context;
    EVP_CIPHER_CTX_init(&context);

    if (0 == EVP_DecryptInit_ex(&context, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        THROW_CRYPTO_ERROR(lastCryptoError());
    }
    if (0 == EVP_DecryptInit_ex(&context, NULL, NULL, &key[0], &iv[0])) {
        THROW_CRYPTO_ERROR(lastCryptoError());
    }
    int workingLen{0};
    /**
     * In the following statement we have a narrowing conversion to satisfy the type
     * required for the c API of size_t -> int. Since the caller of this function verifies that
     * the length of cipherText does not exceed the max positive value of an int and this
     * function bring private to this compilation unit we are OK with narrowing
     * conversion.  We use an explicit cast to squelch the compile warning.
     */
    int cipherTextLen{static_cast<int>(cipherText.size())};
    if (0 == EVP_DecryptUpdate(&context, &plainText[0], &workingLen, &cipherText[0], cipherTextLen)) {
        THROW_CRYPTO_ERROR(lastCryptoError());
    }

    int plainTextLen{workingLen};
    std::vector<unsigned char> tagCopy(tag);
    if (0 == EVP_CIPHER_CTX_ctrl(&context, EVP_CTRL_GCM_SET_TAG, TAG_LEN, &tagCopy[0])) {
        THROW_CRYPTO_ERROR(lastCryptoError());
    }

    /**
     * The next line without the cast would be a harmless widening conversion of an int to size_t.
     * We use an explicit static_cast<size_t> to silence the compile warning.
     */
    if (0 == EVP_DecryptFinal_ex(&context, &plainText[static_cast<size_t>(workingLen)], &workingLen)) {
        THROW_CRYPTO_ERROR(lastCryptoError());
    }
    plainTextLen += workingLen;
    if (0 == EVP_CIPHER_CTX_cleanup(&context)) {
        THROW_CRYPTO_ERROR(lastCryptoError());
    }
}

} // namespace null


namespace secp
{

void composeAesGcm256EncryptedContent(const std::string& tag,
                                      const std::string& iv,
                                      const std::string& cipherText,
                                      std::string& encryptedContent)
{
    size_t tagLen{tag.length()};
    if (tagLen != TAG_LEN) {
        THROW_CRYPTO_ERROR(lengthFormatError("tag", tagLen, TAG_LEN));
    }
    size_t ivLen{iv.length()};
    if (ivLen != IV_LEN) {
        THROW_CRYPTO_ERROR(lengthFormatError("iv", ivLen, IV_LEN));
    }
    if (!cipherText.length()) {
        THROW_CRYPTO_ERROR("Cipher Text has zero length!");
    }

    encryptedContent.reserve(TAG_LEN + IV_LEN + cipherText.size());
    std::copy(tag.begin(), tag.end(), std::back_inserter(encryptedContent));
    std::copy(iv.begin(), iv.end(), std::back_inserter(encryptedContent));
    std::copy(cipherText.begin(), cipherText.end(), std::back_inserter(encryptedContent));
}

void parseAesGcm256EncryptedContent(const std::string& encryptedContent,
                                    std::string& tag,
                                    std::string& iv,
                                    std::string& cipherText)
{
    size_t encLen{encryptedContent.length()};
    if (encLen < (TAG_LEN + IV_LEN)) {
        THROW_CRYPTO_ERROR("Encrypted content is not long enough to contain required elements");
    } else if (encLen == (TAG_LEN + IV_LEN)) {
        THROW_CRYPTO_ERROR("Encrypted content has zero length cipher text.");
    }

    tag.assign(encryptedContent.begin(), encryptedContent.begin() + TAG_LEN);
    iv.assign(encryptedContent.begin() + TAG_LEN, encryptedContent.begin() + TAG_LEN + IV_LEN);
    cipherText.assign(encryptedContent.begin() + TAG_LEN + IV_LEN, encryptedContent.end());
}

void authAes256GcmEncrypt_4(const std::vector<unsigned char>& key,
                            const std::vector<unsigned char>& iv,
                            const std::vector<unsigned char>& plainText,
                            std::vector<unsigned char>& tag,
                            std::vector<unsigned char>& cipherText)
{
    size_t keyLen{key.size()};
    if (keyLen != KEY_LEN) {
        THROW_CRYPTO_ERROR(lengthFormatError("key", keyLen, KEY_LEN));
    }
    size_t ivLen{iv.size()};
    if (ivLen != IV_LEN) {
        THROW_CRYPTO_ERROR(lengthFormatError("iv", ivLen, IV_LEN));
    }
    size_t plainTextLen{plainText.size()};
    if (!plainTextLen) {
        THROW_CRYPTO_ERROR("Plain Text has zero length!");
    } else if (plainTextLen > std::numeric_limits<int>::max()) {
        THROW_CRYPTO_ERROR("Plain Text exceeds max length for an int!");
    }

    basicEncryptAesGcm256_4(key, iv, plainText, cipherText, tag);
}

void authAes256GcmDecrypt_4(const std::vector<unsigned char>& key,
                            const std::vector<unsigned char>& tag,
                            const std::vector<unsigned char>& iv,
                            const std::vector<unsigned char>& cipherText,
                            std::vector<unsigned char>& plainText)
{
    size_t keyLen{key.max_size()};
    if (keyLen != KEY_LEN) {
        THROW_CRYPTO_ERROR(lengthFormatError("key", keyLen, KEY_LEN));
    }
    size_t tagLen{tag.size()};
    if (tagLen != TAG_LEN) {
        THROW_CRYPTO_ERROR(lengthFormatError("tag", tagLen, TAG_LEN));
    }
    size_t ivLen{iv.size()};
    if (ivLen != IV_LEN) {
        THROW_CRYPTO_ERROR(lengthFormatError("iv", ivLen, IV_LEN));
    }
    size_t cipherTextLen{cipherText.size()};
    if (!cipherTextLen) {
        THROW_CRYPTO_ERROR("Cipher Text has zero length!");
    } else if (cipherTextLen > std::numeric_limits<int>::max()) {
        THROW_CRYPTO_ERROR("Cipher Text exceeds max length for an int!");
    }

    basicDecryptAesGcm256_4(key, tag, iv, cipherText, plainText);
}

} // namespace secp