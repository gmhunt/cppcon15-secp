//
// Created by Gwendolyn Hunt on 9/1/15.
//

#ifndef SCENARIO_2_AESGCM256_1_HPP_H
#define SCENARIO_2_AESGCM256_1_HPP_H

#include <string>
#include <vector>

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


namespace secp
{

/**
 *  Encryption function using OpenSSL
 *
 *  Algorithm AES-GCM-256
 *
 *  @param key              IN  encryption key: pointer to unsigned char array. This must be 256-bits
 *                              in length.
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
                            unsigned char *tag);

/**
 *  Decryption function using OpenSSL
 *
 *  Algorithm AES-GCM-256
 *
 *  @param key              IN  encryption key: pointer to unsigned char array. This must be 256-bits
 *                              in length.
 *  @param tag              in  pointer to a unsigned char array with length of 128-bits in length.
 *  @param iv               IN  initialization vector: pointer to unsigned char array with length of 96-bits.
 *  @param cipherText       IN  pointer unsigned char array with.
 *  @param cipherTextLen    IN  unsigned int of the length of cipherText.
 *  @param plaintText       OUT pointer to unsigned char array of text that will be encrypted.
 *  @param plainTextLen     OUT length of plainText
 *
 *  @return                 SUCCESS == 1
 *                          FAILURE == 0
 */
int basicDecryptAesGcm256_1(const unsigned char *key,
                            const unsigned char *tag,
                            const unsigned char *iv,
                            const unsigned char *cipherText,
                            const int cipherTextLen,
                            unsigned char *plainText,
                            int &plainTextLen);

/**
 *
 */
std::string combineAesGcm256EncryptedElements_1(const unsigned char *tag,
                                                const int tagLen,
                                                const unsigned char *iv,
                                                const int ivLen,
                                                const unsigned char *cipherText,
                                                const int cipherTextLen);

int cipherTextLength(const std::string& combinedElements);

std::string authAes256GcmEncrypt_1(const std::string &key,
                                   const std::string &iv,
                                   const std::string &ptext);

std::string authAes256GcmDecrypt_1(const std::string& key,
                                   const std::string& combinedElements);

}
#endif //SCENARIO_2_AESGCM256_1_HPP_H
