#include "CryptoController.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>


namespace secp
{

CryptoController::CryptoController()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

}

CryptoController::~CryptoController()
{
    EVP_cleanup();
}

} // namespace scep
