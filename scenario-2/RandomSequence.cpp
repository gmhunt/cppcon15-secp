//
// Created by Gwendolyn Hunt on 9/1/15.
//

#include "RandomSequence.hpp"
#include "openssl/aes.h"
#include "openssl/evp.h"
#include "openssl/rand.h"
#include "CryptoError.hpp"

#include <sstream>

namespace secp
{

unsigned byteSize(const secp::Random bits)
{
    unsigned size{0};
    switch (bits) {
        case secp::Random::SIZE_96_BITS:
            size = 12;
            break;
        case secp::Random::SIZE_128_BITS:
            size = 16;
            break;
        case secp::Random::SIZE_256_BITS:
            size = 32;
            break;
        default:
            //THROW_CRYPTO_ERROR(boost::str(boost::format(randomSaltBytesFailure) % keyLen % lastCryptoError()));
            break;
    }
    return size;
}

std::string unknownBitLengthError(const secp::Random bits);

std::string bitsAsString(const secp::Random bits)
{
    std::string bs;
    switch (bits) {
        case secp::Random::SIZE_96_BITS:
            bs = "96";
            break;
        case secp::Random::SIZE_128_BITS:
            bs = "128";
            break;
        case secp::Random::SIZE_256_BITS:
            bs = "256";
            break;
        default:
            THROW_CRYPTO_ERROR(unknownBitLengthError(bits));
            break;
    }
    return bs;
}

std::string unknownBitLengthError(const secp::Random bits)
{
    std::stringstream ss;
    ss << "Unknown bit length: " << bitsAsString(bits);
    return ss.str();
}
/**
 * Generates a random sequence of bytes using a cryptographic quality Key Derivation Function.
 * Suitable for generating:
 * - AES 256 Keys
 * - Initialization vectors
 */
std::vector<unsigned char> generateRandomSequence(const Random bits)
{
    unsigned len = byteSize(bits);
    int keyLen = static_cast<int>(len);

    std::vector<unsigned char> aesKey(32,  0);
    std::vector<unsigned char> aesPass(len, 0);
    std::vector<unsigned char> aesSalt(len, 0);

    if (0 == RAND_bytes(&aesPass[0], keyLen)) {
        std::stringstream ss;
        ss << "Random generartion failure for keylen: " << keyLen << ", error: " << lastCryptoError();
        THROW_CRYPTO_ERROR(ss.str());
    }

    if (0 == RAND_bytes(&aesSalt[0], 8)) {
        std::stringstream ss;
        ss << "Random generation failure for 8-byte salt, error: " << lastCryptoError();
        THROW_CRYPTO_ERROR(ss.str());
    }

    int rc(0);
    switch (bits) {
        case Random::SIZE_96_BITS:
        case Random::SIZE_128_BITS:
            rc = EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), &aesSalt[0], &aesPass[0], keyLen, 5, &aesKey[0], NULL);
            break;
        case Random::SIZE_256_BITS:
            rc = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), &aesSalt[0], &aesPass[0], keyLen, 5, &aesKey[0], NULL);
            break;
        default:
            THROW_CRYPTO_ERROR(unknownBitLengthError(bits));
            break;
    }

    if (0 == rc) {
        std::stringstream ss;
        ss << "BytesToKey failed for keylen: " << keyLen << ", error: " << lastCryptoError();
        THROW_CRYPTO_ERROR(ss.str());
    }
    aesKey.resize(len);
    return aesKey;
}

} // namespace secp