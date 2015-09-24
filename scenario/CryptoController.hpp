#ifndef CRYPTO_CONTROLLER_HPP_
#define CRYPTO_CONTROLLER_HPP_

#include <boost/noncopyable.hpp>
#include <string>

namespace secp
{

/**
 *  This class provides RAII wrapper around OpenSSL
 *  startup and cleanup functions.
 *
 * If you were to use the FIPS validated cryptology this
 * class would be a good place to call FIPS_set_mode()
 * to enable FIPS algorithms and log the results as required
 * for FIPS 140-2 compliance.
 */

class CryptoController : private boost::noncopyable
{
public:
	CryptoController();

    virtual ~CryptoController();

private:

};


} // namespace secp

#endif /* CRYPTO_CONTROLLER_HPP_ */
