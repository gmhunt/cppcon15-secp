//
// Created by Gwendolyn Hunt on 9/1/15.
//

#ifndef RANDOM_SEQUENCE_HPP_
#define RANDOM_SEQUENCE_HPP_

#include "openssl/aes.h"
#include "openssl/evp.h"
#include "openssl/rand.h"
#include "CryptoError.hpp"
#include <string>
#include <vector>

namespace secp
{

enum class Random {
    SIZE_96_BITS = 96,
    SIZE_128_BITS = 128,
    SIZE_256_BITS = 256
};

unsigned byteSize(const secp::Random bits);

std::string bitsAsString(const secp::Random bits);

std::vector<unsigned char> generateRandomSequence(const Random bits);

} // namespace secp

#endif //RANDOM_SEQUENCE_HPP_
