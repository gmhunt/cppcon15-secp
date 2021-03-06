//
// Created by Gwendolyn Hunt on 9/9/15.
//

#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "CryptoError.hpp"
#include "Logger.hpp"
#include "Hmac.hpp"

#include <sstream>
#include <vector>

namespace 
{
const unsigned KEY_LEN(32); //SHA256 length in bytes

struct SafeHmacContext
{
    SafeHmacContext()
        : context_()
    {
        HMAC_CTX_init(&context_);
        secp::log(secp::DEBUG, "HMAC Context initialized");
    }

    ~SafeHmacContext()
    {
        HMAC_CTX_cleanup(&context_);
        secp::log(secp::DEBUG, "HMAC Context cleanup successful");
    }

    HMAC_CTX context_;
};

}

namespace secp
{

/**
 * This function generates a HMAC Using SHA256.  Requires a 256-bit key
 * and returns a 256-bit HMAC.  We use std::string as the interface because
 * it simplifies use with Google protobuf.
 */
std::string generateHmac(const std::string& key, const std::string& message)
{
    std::vector<unsigned char> k{key.begin(), key.end()};
    int keyLen{static_cast<int>(k.size())};
    if (keyLen != KEY_LEN) {
        std::stringstream ss;
        ss << "Incorrect keylen: " << keyLen << ", require " << KEY_LEN << "bytes, error: " << lastCryptoError();
        THROW_CRYPTO_ERROR(ss.str());
    }
    
    std::vector<unsigned char> d{message.begin(), message.end()};
    int dataLen{static_cast<int>(d.size())};
    std::vector<unsigned char> hmac(KEY_LEN);
    unsigned int hmacLen{static_cast<unsigned int>(hmac.size())};

    SafeHmacContext c;

    int rc{0};
    rc = HMAC_Init_ex(&c.context_, &k[0], keyLen, EVP_sha256(), NULL);
    if (rc == 0) {
        std::stringstream ss;
        ss << "Failed initializing HMAC context, error: " << lastCryptoError();
        THROW_CRYPTO_ERROR(ss.str());
    }
    rc = HMAC_Update(&c.context_, &d[0], dataLen);
    if (rc == 0) {
        std::stringstream ss;
        ss << "Failed HMAC update, error: " << lastCryptoError();
        THROW_CRYPTO_ERROR(ss.str());
    }
    rc = HMAC_Final(&c.context_, &hmac[0], &hmacLen);
    if (rc == 0) {
        std::stringstream ss;
        ss << "Finalizing HMAC failed, error: " << lastCryptoError();
        THROW_CRYPTO_ERROR(ss.str());
    }

    return std::string(hmac.begin(), hmac.end());
}

} // namespace secp
