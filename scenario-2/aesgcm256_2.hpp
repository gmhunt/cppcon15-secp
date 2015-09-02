//
// Created by Gwendolyn Hunt on 9/1/15.
//

#ifndef SCENARIO_2_AESGCM256_2_HPP_
#define SCENARIO_2_AESGCM256_2_HPP_

#include <string>
#include <vector>

namespace secp
{

void authAes256GcmEncrypt_1(const std::string& key,
                            const std::string& iv,
                            const std::string& plainText,
                            std::string& tag,
                            std::string& cipherText);

void authAes256GcmDecrypt_1(const std::string& key,
                            const std::string& tag,
                            const std::string& iv,
                            const std::string& cipherText,
                            std::string& plainText);

}
#endif //SCENARIO_2_AESGCM256_2_HPP_
