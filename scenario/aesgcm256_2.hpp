//
// Created by Gwendolyn Hunt on 9/1/15.
//

#ifndef SCENARIO_2_AESGCM256_2_HPP_
#define SCENARIO_2_AESGCM256_2_HPP_

#include <string>
#include <vector>

namespace secp
{

void authAes256GcmEncrypt_2(const std::vector<unsigned char>& key,
                            const std::vector<unsigned char>& iv,
                            const std::vector<unsigned char>& plainText,
                            std::vector<unsigned char>& tag,
                            std::vector<unsigned char>& cipherText);

/**
 *
 */
void authAes256GcmDecrypt_2(const std::vector<unsigned char>& key,
                            const std::vector<unsigned char>& tag,
                            const std::vector<unsigned char>& iv,
                            const std::vector<unsigned char>& cipherText,
                            std::vector<unsigned char>& plainText);

}
#endif //SCENARIO_2_AESGCM256_2_HPP_
