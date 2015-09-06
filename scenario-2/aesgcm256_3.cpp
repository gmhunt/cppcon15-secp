//
// Created by ghunt on 8/31/15.
//

#include "boost/format.hpp"
#include "aesgcm256_3.hpp"
#include "CryptoError.hpp"
#include "openssl/evp.h"
#include "openssl/err.h"
#include <string.h>
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
const size_t KEY_LEN(32);

const std::string lengthErrorFormat("Invalid %1% length: '%2%. Should be: '%3%");

void basicEncryptAesGcm256_3(const std::vector<unsigned char>& key,
                             const std::vector<unsigned char>& iv,
                             const std::vector<unsigned char>& plainText,
                             std::vector<unsigned char>& cipherText,
                             std::vector<unsigned char>& tag)
{
    EVP_CIPHER_CTX context;
    EVP_CIPHER_CTX_init(&context);

    if (0 == EVP_EncryptInit_ex(&context, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        THROW_CRYPTO_ERROR(secp::lastCryptoError());
    }
    if (0 == EVP_EncryptInit_ex(&context, NULL, NULL, &key[0], &iv[0])) {
        THROW_CRYPTO_ERROR(secp::lastCryptoError());
    }

    int plainTextLen{static_cast<int>(plainText.size())};
    cipherText.clear();
    cipherText.resize(plainTextLen);
    int cipherTextLen{0};

    if (0 == EVP_EncryptUpdate(&context, &cipherText[0], &cipherTextLen, &plainText[0], plainTextLen)) {
        THROW_CRYPTO_ERROR(secp::lastCryptoError());
    }
    if (0 == EVP_EncryptFinal_ex(&context, &cipherText[cipherTextLen], &cipherTextLen)) {
        THROW_CRYPTO_ERROR(secp::lastCryptoError());
    }
    if (0 ==  EVP_CIPHER_CTX_ctrl(&context, EVP_CTRL_GCM_GET_TAG, TAG_LEN, &tag[0])) {
        THROW_CRYPTO_ERROR(secp::lastCryptoError());
    }
    if (0 == EVP_CIPHER_CTX_cleanup(&context)) {
        THROW_CRYPTO_ERROR(secp::lastCryptoError());
    }
}

void basicDecryptAesGcm256_3(const std::vector<unsigned char>& key,
                             const std::vector<unsigned char>& tag,
                             const std::vector<unsigned char>& iv,
                             const std::vector<unsigned char>& cipherText,
                             std::vector<unsigned char>& plainText)
{
    EVP_CIPHER_CTX context;
    EVP_CIPHER_CTX_init(&context);

    if (0 == EVP_DecryptInit_ex(&context, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        THROW_CRYPTO_ERROR(secp::lastCryptoError());
    }
    if (0 == EVP_DecryptInit_ex(&context, NULL, NULL, &key[0], &iv[0])) {
        THROW_CRYPTO_ERROR(secp::lastCryptoError());
    }
    int workingLen{0};
    if (0 == EVP_DecryptUpdate(&context, &plainText[0], &workingLen, &cipherText[0], cipherText.size())) {
        THROW_CRYPTO_ERROR(secp::lastCryptoError());
    }

    int plainTextLen{workingLen};
    std::vector<unsigned char> tagCopy(tag);
    if (0 == EVP_CIPHER_CTX_ctrl(&context, EVP_CTRL_GCM_SET_TAG, TAG_LEN, &tagCopy[0])) {
        THROW_CRYPTO_ERROR(secp::lastCryptoError());
    }
    if (0 == EVP_DecryptFinal_ex(&context, &plainText[workingLen], &workingLen)) {
        THROW_CRYPTO_ERROR(secp::lastCryptoError());
    }
    plainTextLen += workingLen;
    if (0 == EVP_CIPHER_CTX_cleanup(&context)) {
        THROW_CRYPTO_ERROR(secp::lastCryptoError());
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
        THROW_CRYPTO_ERROR(boost::str(boost::format(
                lengthErrorFormat) % "tag" % tagLen % TAG_LEN));
    }
    size_t ivLen{iv.length()};
    if (ivLen != IV_LEN) {
        THROW_CRYPTO_ERROR(boost::str(boost::format(
                lengthErrorFormat) % "iv" % ivLen % IV_LEN));
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

void authAes256GcmEncrypt_3(const std::vector<unsigned char>& key,
                            const std::vector<unsigned char>& iv,
                            const std::vector<unsigned char>& plainText,
                            std::vector<unsigned char>& tag,
                            std::vector<unsigned char>& cipherText)
{
    size_t keyLen{key.size()};
    if (keyLen != KEY_LEN) {
        THROW_CRYPTO_ERROR(boost::str(boost::format(
                lengthErrorFormat) % "key" % keyLen % KEY_LEN));
    }
    size_t ivLen{iv.size()};
    if (ivLen != IV_LEN) {
        THROW_CRYPTO_ERROR(boost::str(boost::format(
                lengthErrorFormat) % "iv" % ivLen % IV_LEN));
    }
    if (!plainText.size()) {
        THROW_CRYPTO_ERROR("Plain Text has zero length!");
    }

    basicEncryptAesGcm256_3(key, iv, plainText, cipherText, tag);
}

void authAes256GcmDecrypt_3(const std::vector<unsigned char>& key,
                            const std::vector<unsigned char>& tag,
                            const std::vector<unsigned char>& iv,
                            const std::vector<unsigned char>& cipherText,
                            std::vector<unsigned char>& plainText)
{
    size_t keyLen{key.size()};
    if (keyLen != KEY_LEN) {
        THROW_CRYPTO_ERROR(boost::str(boost::format(
                lengthErrorFormat) % "key" % keyLen % KEY_LEN));
    }
    size_t tagLen{tag.size()};
    if (tagLen != TAG_LEN) {
        THROW_CRYPTO_ERROR(boost::str(boost::format(
                lengthErrorFormat) % "tag" % tagLen % TAG_LEN));
    }
    size_t ivLen{iv.size()};
    if (ivLen != IV_LEN) {
        THROW_CRYPTO_ERROR(boost::str(boost::format(
                lengthErrorFormat) % "iv" % ivLen % IV_LEN));
    }
    if (!cipherText.size()) {
        THROW_CRYPTO_ERROR("Cipher Text has zero length!");
    }

    basicDecryptAesGcm256_3(key, tag, iv, cipherText, plainText);
}

} // namespace secp