#include <boost/algorithm/hex.hpp>
#include "boost/format.hpp"
#include "boost/test/unit_test.hpp"

#include "aesgcm256_1.hpp"
#include "Logger.hpp"
#include "TestCryptoController.hpp"
#include "DemoWrapper.hpp"
#include "CryptoError.hpp"
#include "RandomSequence.hpp"

#include <iostream>
#include <thread>

namespace
{

std::string bin2hex(const std::vector<unsigned char>& source)
{
    std::string bin{source.begin(), source.end()};
    std::string hexString;
    boost::algorithm::hex(source, std::back_inserter(hexString));
    return hexString;
}

bool isEqualSequence(const std::vector<unsigned char>& l, std::vector<unsigned char>& r)
{
    /**
     * Not the most efficient but works for this test.
     */
    std::string lhs(l.begin(), l.end());
    std::string rhs(r.begin(), r.end());

    return (lhs.compare(rhs) == 0);
}

void testGCMEncryption(const std::string &testName, const unsigned iterations)
{
    std::vector<unsigned char> origPlainText;

    // Generate plain text. Adding an uneven block so we don't land on key length boundaries.
    //
    std::string unevenBlock{"CAFE8730921uiod1kjd9d2188092184092184lk"};
    unsigned origPlainTextLen = static_cast<unsigned int>((iterations * 32) + unevenBlock.length());

    origPlainText.reserve(origPlainTextLen);
    for (unsigned i(0); i < iterations; ++i) {
        std::vector<unsigned char> element = secp::generateRandomSequence(secp::Random::SIZE_256_BITS);
        origPlainText.insert(origPlainText.end(), element.begin(), element.end());
    }
    origPlainText.insert(origPlainText.end(), unevenBlock.begin(), unevenBlock.end());

    std::vector<unsigned char> key = secp::generateRandomSequence(secp::Random::SIZE_256_BITS);
    std::vector<unsigned char> iv = secp::generateRandomSequence(secp::Random::SIZE_96_BITS);
    std::vector<unsigned char> tag;

    std::stringstream ssB;
    ssB << "\n### " << testName << " --------------------------------------------------------"
        << "\n### aesKey..............size:[" << key.size() << "], value: " << bin2hex(key)
        << "\n### aesGcmIV............size:[" << iv.size() << "], value: " << bin2hex(iv)
        << "\n### source plain text...size:[" << origPlainText.size() << "], value: " << bin2hex(origPlainText);
    secp::log(secp::INFO, ssB.str());

    std::vector<unsigned char> cipherText;
    std::vector<unsigned char> decryptPlainText;


    secp::log(secp::INFO, "encrypting...");
    int cipherTextLen(origPlainTextLen);
    tag.resize(16);
    cipherText.resize(cipherTextLen);
    secp::encryptAesGcm256_1(&key[0], &iv[0], &origPlainText[0], origPlainTextLen, &cipherText[0], cipherTextLen, &tag[0]);
    std::stringstream ssE;
    ssE << "\n### ENCRYPT AEAD TAG....size:[" << tag.size() << "], value: " << bin2hex(tag)
        << "\n### ENCRYPT cipher text.size:[" << cipherText.size() << "], value: " << bin2hex(cipherText);
    secp::log(secp::INFO, ssE.str());


    secp::log(secp::INFO, "decrypting...");
    cipherTextLen = cipherText.size();
    int decryptPlainTextLen(cipherTextLen);
    decryptPlainText.resize(decryptPlainTextLen);
    int rc = secp::decryptAesGcm256_1(&key[0], &tag[0], &iv[0], &cipherText[0], cipherTextLen, &decryptPlainText[0], decryptPlainTextLen);
    secp::log(secp::INFO, std::to_string(rc));
    std::stringstream ssA;
    ssA << "\n### aesKey..............size:[" << key.size() << "], value: " << bin2hex(key)
        << "\n### aesGcmIV............size:[" << iv.size() << "], value: " << bin2hex(iv)
        << "\n### AEAD TAG............size:[" << tag.size() << "], value: " << bin2hex(tag)
        << "\n### DECRYPT cipher text.size:[" << cipherText.size() << "], value: " << bin2hex(cipherText)
        << "\n### DECRYPT plain text..size:[" << decryptPlainTextLen << "], value: " << bin2hex(decryptPlainText);
    secp::log(secp::INFO, ssA.str());

    //  Compare decrypted to original plaintext.
    //
    auto matches = isEqualSequence(decryptPlainText, origPlainText);
    BOOST_CHECK(matches);
    if (matches) {
        secp::log(secp::INFO, "Success. Decrypt matches original!");
    }
}

void checkCrypto()
{
    TestCryptoController::instance();
}

} // namespace null


BOOST_AUTO_TEST_SUITE(aes_encrypt_1)
BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_1)
{
    try {

        secp::log(secp::INFO, "BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_1) - starting...");
        checkCrypto();
        
        testGCMEncryption("AES256-GCM-1", 2);

        secp::log(secp::INFO, "BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_1) - end.");

    } catch(std::exception& e) {
        std::cerr << "CAUGHT std::exception. " << e.what() << ". Shutting down..\n\n";
    }
}
BOOST_AUTO_TEST_SUITE_END()

