#ifndef CRYPTO_CONTROLLER_HPP_
#define CRYPTO_CONTROLLER_HPP_

#include <boost/noncopyable.hpp>
#include <string>

namespace secp
{

/**
 *  This class provides RAII wrapper around OpenSSL
 *  startup and cleanup functions
 */

class CryptoController : private boost::noncopyable
{
public:
	CryptoController);

    virtual ~CryptoController();

private:

};


} // namespace secp

#endif /* CRYPTO_CONTROLLER_HPP_ */
