//
// Created by Gwendolyn Hunt on 9/1/15.
//

#include "RandomBytes.hpp"
#include "openssl/aes.h"
#include "openssl/evp.h"
#include "openssl/rand.h"
#include "CryptoError.hpp"

namespace secp
{

std::vector<unsigned char> generateRandomSequence(const Random bits)
{
    unsigned keyLen = static_cast<unsigned>(bits/8);

    std::vector<unsigned char> aesKey(keyLen, 0);
    std::vector<unsigned char> aesPass(keyLen, 0);
    std::vector<unsigned char> aesSalt(keyLen, 0);

    if (0 == RAND_bytes(&aesPass[0], keyLen)) {
        THROW_CRYPTO_ERROR(boost::str(boost::format(randomSaltBytesFailure) % keyLen % lastCryptoError()));
    }

    if (0 == RAND_bytes(&aesSalt[0], 8)) {
        THROW_CAP_CRYPTO_ERROR(boost::str(boost::format(randomPassBytesFailure) % 8 % lastCryptoError()));
    }

    int rc(0);
    switch (bits) {
        case Random::SIZE_96_BITS:
        {
            /**
             * Even though we only need 96-bits, we need to size the aesKey to 128-bits
             * since we are using the EVP_aes_128_cbc() algorithm.
             */
            unsigned keyLen128 = static_cast<unsigned>(Random::SIZE_128_BITS/8);
            aesKey.resize(keyLen128);
            rc = EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), &aesSalt[0], &aesPass[0], keyLen128, 5, &aesKey[0], NULL);
            aesKey.resize(keyLen);
        }
            break;
        case Random::SIZE_128_BITS:
            rc = EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), &aesSalt[0], &aesPass[0], keyLen, 5, &aesKey[0], NULL);
            break;
        case Random::SIZE_256_BITS:
            rc = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), &aesSalt[0], &aesPass[0], keyLen, 5, &aesKey[0], NULL);
            break;
        default:
            THROW_CAP_CRYPTO_ERROR(boost::str(boost::format(unknownBitLength) % bits));
            break;
    }
    if (0 == rc) {
        THROW_CAP_CRYPTO_ERROR(boost::str(boost::format(bytesToKeyFailure) % keyLen % lastCryptoError()));
    }

    return aesKey;
}

} // namespace secp