//----------------------------------------
// CryptoError.hpp
//
//  Created on: Dec 14, 2010
//      Author: ghunt
//----------------------------------------


#ifndef CRYPTO_ERROR_HPP_
#define CRYPTO_ERROR_HPP_

#include "openssl/err.h"
#include <string.h>
#include <string>


namespace secp
{

class CryptoError : public virtual std::exception
{
public:
    CryptoError(const char* fileName, unsigned int lineNumber, const char* message);

    CryptoError(const char* fileName, unsigned int lineNumber, const std::string& message);

    virtual ~CryptoError() throw();

    virtual const char* what() const throw ();

private:
    std::string whatString_;
};

/**
 * returns last error from OpenSSL
 * as a formatted string.
 */
std::string lastCryptoError();

} // end of namespace secp


// Helper Macros to make sure we pass __FILE__ and __LINE__
#define THROW_CRYPTO_ERROR(message) throw (secp::CryptoError(__FILE__, __LINE__, message))

#endif /* CRYPTO_ERROR_HPP_ */
