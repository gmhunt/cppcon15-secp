//----------------------------------------
// CryptoError.hpp
//
//  Created on: Dec 14, 2010
//      Author: ghunt
//----------------------------------------


#ifndef CRYPTO_ERROR_HPP_
#define CRYPTO_ERROR_HPP_

#include <string>


namespace secp
{

class CryptoError : public virtual std::exception
{
public:
    CryptoError(const char* fileName, unsigned int lineNumber, const char* message)
        : whatString_(std::string(fileName) + ":" + std::to_string(lineNumber) + " error: " + std::string(message))
    {}

    CryptoError(const char* fileName, unsigned int lineNumber, const std::string& message)
        : whatString_(std::string(fileName) + ":" + std::to_string(lineNumber) + " error: "  + message)
    {}

    virtual ~CryptoError() throw()
    {}

    virtual const char* what() const throw ()
    {
        return whatString_.c_str();
    }

private:
    std::string whatString_;
};

} // end of namespace secp


// Helper Macros to make sure we pass __FILE__ and __LINE__
#define THROW_CRYPTO_ERROR(message) throw (secp::CryptoError(__FILE__, __LINE__, message))

#endif /* CRYPTO_ERROR_HPP_ */
