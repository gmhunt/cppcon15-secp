//
// Created by Gwendolyn Hunt on 9/1/15.
//

#ifndef SCENARIO_2_AESGCM256_4_HPP_
#define SCENARIO_2_AESGCM256_4_HPP_

#include <string>
#include <vector>

namespace secp
{

void composeAesGcm256EncryptedContent(const std::string &tag,
                                      const std::string &iv,
                                      const std::string &cipherText,
                                      std::string &encryptedMessage);

void parseAesGcm256EncryptedContent(const std::string &encryptedMessage,
                                    std::string &tag,
                                    std::string &iv,
                                    std::string &cipherText);

/**
 *
 */
void authAes256GcmEncrypt_4(const std::vector<unsigned char> &key,
                            const std::vector<unsigned char> &iv,
                            const std::vector<unsigned char> &plainText,
                            std::vector<unsigned char> &tag,
                            std::vector<unsigned char> &cipherText);

/**
 *
 */
void authAes256GcmDecrypt_4(const std::vector<unsigned char> &key,
                            const std::vector<unsigned char> &tag,
                            const std::vector<unsigned char> &iv,
                            const std::vector<unsigned char> &cipherText,
                            std::vector<unsigned char> &plainText);

}
#endif //SCENARIO_2_AESGCM256_4_HPP_
