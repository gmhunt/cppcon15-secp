#include "CryptoError.hpp"
#include "openssl/err.h"
#include <string.h>
#include <string>


namespace secp
{

CryptoError::CryptoError(const char* fileName, unsigned int lineNumber, const char* message)
    : whatString_(std::string(fileName) + ":" + std::to_string(lineNumber) + " error: " + std::string(message))
{}

CryptoError::CryptoError(const char* fileName, unsigned int lineNumber, const std::string& message)
    : whatString_(std::string(fileName) + ":" + std::to_string(lineNumber) + " error: "  + message)
{}

CryptoError::~CryptoError() throw()
{}

const char* CryptoError::what() const throw ()
{
    return whatString_.c_str();
}

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

} // end of namespace secp
