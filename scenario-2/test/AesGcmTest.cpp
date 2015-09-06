#include <boost/algorithm/hex.hpp>
#include "boost/format.hpp"
#include "boost/test/unit_test.hpp"

#include "TestCryptoController.hpp"
#include "DemoWrapper.hpp"
#include "CryptoError.hpp"
#include "RandomSequence.hpp"

#include <algorithm>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>

namespace
{

/**
 * Utility functions
 */
std::string bin2Hex(const std::vector<unsigned char>& source)
{
    std::string bin{source.begin(), source.end()};
    std::string hexString;
    boost::algorithm::hex(source, std::back_inserter(hexString));
    return hexString;
}

const std::string genFailure("Generated Key, length in bits:[%1%], value in hex: '%2%'");

/**
 * Removes duplicate elements and returns number of unique elements.
 */
unsigned removeDuplicates(std::vector<std::string>& v)
{
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());

    return v.size();
}

bool isEqualSequence(const std::vector<unsigned char>& l, std::vector<unsigned char>& r)
{
    return std::equal<std::vector<unsigned char>, std::vector<unsigned char>>(l.begin(), l.end(), r.begin());
}

/**
 * Core encrypt/decrypt test function
 */
void testGCMEncryption(const std::string& testName, const unsigned iterations, DemoWrapper& tester)
{
    std::vector<unsigned char> origPlainText;

    /**
     * Generate plain text. Adding an uneven block so we don't land on key length boundaries.
     */
    std::string unevenBlock{"CAFE8730921uiod1kjd9d2188092184092184lk"};
    unsigned origPlainTextLen{(iterations * 32) + unevenBlock.length()};

    origPlainText.reserve();
    for (unsigned i(0); i < iterations; ++i) {
        std::vector<unsigned char> element = secp::generateRandomSequence(secp::Random::SIZE_256_BITS);
        origPlainText.insert(origPlainText.end(), element.begin(), element.end());
    }
    origPlainText.insert(origPlainText.end(), unevenBlock.begin(), unevenBlock.end());

    std::vector<unsigned char>  key{secp::generateRandomSequence(secp::Random::SIZE_256_BITS)};
    std::vector<unsigned char>  iv{secp::generateRandomSequence(secp::Random::SIZE_96_BITS)};
    std::vector<unsigned char>  tag;

    std::stringstream ssB;
    ssB << "\n### " << testName << " --------------------------------------------------------"
        << "\n### aesKey..............size:[" << key.size() << "], value: " << bin2hex(key)
        << "\n### aesGcmIV............size:[" << iv.size() << "], value: "  << bin2hex(iv)
        << "\n### source plain text...size:[" << origPlainText.size() << "]";
    logDebug(ssB.str());

    std::vector<unsigned char> cipherText;
    std::vector<unsigned char> decryptPlainText;
    tester.encrypt(key, iv, origPlainText, tag, cipherText);
    tester.decrypt(key, tag, iv, cipherText, tag, decryptPlainText);

    std::stringstream ssA;
    ssA << "\n### AEAD TAG............size:[" << tag.length() << "], value: " << bin2hex(tag)
        << "\n### cipher text.........size:[" << cipherText.length() << "]";
    ssA << "\n### decrypt plain text..size:[" << decryptPlainText.length() << "]";
    logDebug(ssA.str());

    /**
     *  Compare decrypted to original plaintext.
     */
    BOOST_CHECK(isEqualSequence(decryptPlainText, origPlainText));

    /**
     * Check for throw on following conditions:
     * - bad key
     * - bad iv
     * - bad cipherText
     * - bad tag
     */
    std::vector<unsigned char> badSeq{secp::generateRandomSequence(secp::Random::SIZE_128_BITS};
    std::vector<unsigned char> badKey{key};
    badKey.insert(badKey.end(), badSeq.begin(), badSeq.end());

    std::vector<unsigned char> badIv{iv};
    badKey.insert(badIv.end(), badSeq.begin(), badSeq.end());

    std::vector<unsigned char> badCipherText{iv};
    badKey.insert(badKey.end(), badSeq.begin(), badSeq.end());

    std::vector<unsigned char> badTag{tag};
    badTag.insert(badKey.end(), badSeq.begin(), badSeq.end());

    std::vector<unsigned char> dummyPlainText;
    BOOST_CHECK_THROW(
            tester.decrypt(badKey, tag, iv, cipherText, tag, dummyPlainText);
            cap::CryptoError);
    BOOST_CHECK_THROW(
            tester.decrypt(key, tag, badIv, cipherText, tag, dummyPlainText);
            cap::CryptoError);
    BOOST_CHECK_THROW(
            tester.decrypt(key, tag, iv, badCipherText, tag, dummyPlainText);
            cap::CryptoError);
    BOOST_CHECK_THROW(
            tester.decrypt(key, tag, iv, cipherText, badTag, dummyPlainText);
            cap::CryptoError);
}

void testRandomSequence(const unsigned iterations, const secp::Random bitsSize)
{
    std::string bits{std::to_string<unsigned>(bitsSize)};

    std::vector<std::string> vec;
    for (unsigned i(0); i < iterations; ++i) {
        std::vector<unsigned char> sequence{secp::generateRandomSequence(bitsSize};
        vec.emplace_back(sequence.begin(), sequence.end());
        unsigned bitLen = sequence.size() * 8;
        BOOST_CHECK(bitLen == bits);
    }
    unsigned unique = removeDuplicates(vec);
    BOOST_CHECK(unique == iterations);
    if (unique == iterations) {
        logDebug(boost::str(boost::format("Successfully generated %1% unique %2%-bit sequences") % iterations % bits));
    } else {
        unsigned duplicates(iterations - unique);
        logDebug(boost::str(boost::format("Failure: Generated %1% duplicate %2%-bit sequences out of %3% iterations") %
                duplicates % bits % iterations));
    }
}

} // namespace null


BOOST_AUTO_TEST_SUITE(random_sequence)
BOOST_AUTO_TEST_CASE(create_random_sequence)
{
    try {

        logInfo("BOOST_AUTO_TEST_CASE(create_random_sequence) - starting...");

        checkCrypto();

        unsigned iterations(1000);
        
	    testRandomSequence(iterations, secp::Random::SIZE_96_BITS);
	    testRandomSequence(iterations, secp::Random::SIZE_128_BITS);
	    testRandomSequence(iterations, secp::Random::SIZE_256_BITS);

        logInfo("BOOST_AUTO_TEST_CASE(create_random_sequence) - end.");

    } catch(std::exception& e) {
        std::cerr << "CAUGHT std::exception. " << e.what() << ". Shutting down..\n\n";
    }
}
BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(aes_encrypt_1)
BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_1)
{
    try {

        logInfo("BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_1) - starting...");

        checkCrypto();
        secp::Demo1Tester demo1Tester;
        testGCMEncryption("AES256-GCM-1", 1201, demo1Tester);

        logInfo("BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_1) - end.");

    } catch(std::exception& e) {
        std::cerr << "CAUGHT std::exception. " << e.what() << ". Shutting down..\n\n";
    }
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(aes_encrypt_2)
BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_2)
{
    try {

        logInfo("BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_2) - starting...");

        checkCrypto();
        secp::Demo2Tester demo2Tester;
        testGCMEncryption("AES256-GCM-1", 1201, demo2Tester);

        logInfo("BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_2) - end.");

    } catch(std::exception& e) {
        std::cerr << "CAUGHT std::exception. " << e.what() << ". Shutting down..\n\n";
    }
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(aes_encrypt_3)
BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_3)
{
    try {

        logInfo("BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_3) - starting...");

        checkCrypto();
        secp::Demo3Tester demo3Tester;
        testGCMEncryption("AES256-GCM-1", 1201, demo3Tester);

        logInfo("BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_3) - end.");

    } catch(std::exception& e) {
        std::cerr << "CAUGHT std::exception. " << e.what() << ". Shutting down..\n\n";
    }
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(aes_encrypt_4)
BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_4)
{
    try {

        logInfo("BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_4) - starting...");

        checkCrypto();
        secp::Demo4Tester demo4Tester;
        testGCMEncryption("AES256-GCM-1", 1201, demo4Tester);

        logInfo("BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_4) - end.");

    } catch(std::exception& e) {
        std::cerr << "CAUGHT std::exception. " << e.what() << ". Shutting down..\n\n";
    }
}
BOOST_AUTO_TEST_SUITE_END()BOOST_AUTO_TEST_SUITE_END()