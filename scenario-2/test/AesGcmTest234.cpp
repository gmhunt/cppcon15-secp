#include <boost/algorithm/hex.hpp>
#include "boost/format.hpp"
#include "boost/test/unit_test.hpp"

#include "Hmac.hpp"
#include "Logger.hpp"
#include "TestCryptoController.hpp"
#include "DemoWrapper.hpp"
#include "CryptoError.hpp"
#include "RandomSequence.hpp"

#include <iostream>
#include <thread>

namespace
{

std::string bin2hex(const std::string& source)
{
    std::string hexString;
    boost::algorithm::hex(source, std::back_inserter(hexString));
    return hexString;
}

std::string bin2hex(const std::vector<unsigned char>& source)
{
    std::string bin{source.begin(), source.end()};
    std::string hexString;
    boost::algorithm::hex(bin, std::back_inserter(hexString));
    return hexString;
}

unsigned removeDuplicates(std::vector<std::string>& v)
{
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());

    return v.size();
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

void testGCMEncryption(const std::string &testName, const unsigned iterations, secp::DemoWrapper &tester)
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
    << "\n### source plain text...size:[" << origPlainText.size() << "]";
    secp::log(secp::INFO, ssB.str());

    std::vector<unsigned char> cipherText;
    std::vector<unsigned char> decryptPlainText;
    secp::log(secp::INFO, "encrypting...");
    tester.encrypt(key, iv, origPlainText, tag, cipherText);
    secp::log(secp::INFO, "decrypting...");
    tester.decrypt(key, tag, iv, cipherText, decryptPlainText);

    std::stringstream ssA;
    ssA << "\n### AEAD TAG............size:[" << tag.size() << "], value: " << bin2hex(tag)
        << "\n### cipher text.........size:[" << cipherText.size() << "]";
    ssA << "\n### decrypt plain text..size:[" << decryptPlainText.size() << "]";
    secp::log(secp::INFO, ssA.str());

    //  Compare decrypted to original plaintext.
    //
    auto matches = isEqualSequence(decryptPlainText, origPlainText);
    BOOST_CHECK(matches);
    if (matches) {
        secp::log(secp::INFO, "Success. Decrypt matches original!");
    }
}

void testGCMEncryption4(const std::string &testName, const unsigned iterations, secp::DemoWrapper &tester)
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
    << "\n### source plain text...size:[" << origPlainText.size() << "]";
    secp::log(secp::INFO, ssB.str());

    std::vector<unsigned char> cipherText;
    std::vector<unsigned char> decryptPlainText;
    secp::log(secp::INFO, "encrypting...");
    tester.encrypt(key, iv, origPlainText, tag, cipherText);
    secp::log(secp::INFO, "decrypting...");
    tester.decrypt(key, tag, iv, cipherText, decryptPlainText);

    std::stringstream ssA;
    ssA << "\n### AEAD TAG............size:[" << tag.size() << "], value: " << bin2hex(tag)
    << "\n### cipher text.........size:[" << cipherText.size() << "]";
    ssA << "\n### decrypt plain text..size:[" << decryptPlainText.size() << "]";
    secp::log(secp::INFO, ssA.str());

    //  Compare decrypted to original plaintext.
    //
    auto matches = isEqualSequence(decryptPlainText, origPlainText);
    BOOST_CHECK(matches);
    if (matches) {
        secp::log(secp::INFO, "Success. Decrypt matches original!");
    }

    // Check for throw on following conditions:
    // - bad key
    // - bad tag
    // - bad iv
    // - bad cipherText
    ///
    std::vector<unsigned char> badSeq = secp::generateRandomSequence(secp::Random::SIZE_128_BITS);
    std::vector<unsigned char> badKey{badSeq};
    std::vector<unsigned char> badIv{badSeq};
    std::vector<unsigned char> badCipherText{badSeq};
    std::vector<unsigned char> badTag{badSeq};

    std::vector<unsigned char> dummyPlainText;
    BOOST_CHECK_THROW(
            tester.decrypt(badKey, tag, iv, cipherText, dummyPlainText),
            secp::CryptoError);
    BOOST_CHECK_THROW(
            tester.decrypt(key, badTag, iv, cipherText, dummyPlainText),
            secp::CryptoError);
    BOOST_CHECK_THROW(
            tester.decrypt(key, tag, badIv, cipherText, dummyPlainText),
            secp::CryptoError);
    BOOST_CHECK_THROW(
            tester.decrypt(key, tag, iv, badCipherText, dummyPlainText),
            secp::CryptoError);
}

// const std::string genFailure("Generated Key, length in bits:[%1%], value in hex: '%2%'");


void testRandomSequence(const unsigned iterations, const secp::Random bits)
{
    auto bitsAsString = secp::bitsAsString(bits);

    std::vector<std::string> vec;
    for (unsigned i(0); i < iterations; ++ i) {
        std::vector<unsigned char> sequence = secp::generateRandomSequence(bits);
        vec.emplace_back(sequence.begin(), sequence.end());
        unsigned byteLen = secp::byteSize(bits);
    }
    auto unique = removeDuplicates(vec);
    BOOST_CHECK(unique == iterations);
    if (unique == iterations) {
        std::stringstream ss;
        ss << "Successfully generated " << iterations << " as " << bitsAsString << "-bit sequences.";
        secp::log(secp::INFO, ss.str());
    } else {
        std::stringstream ss;
        auto duplicates = iterations - unique;
        ss << "Failed:  generated " << duplicates << " duplicate " << bitsAsString << "-bit sequences out of " << iterations;
        secp::log(secp::INFO, ss.str());
    }
}

void checkCrypto()
{
    TestCryptoController::instance();
}

std::string convertSequence(const std::vector<unsigned char>& sequence)
{
    return std::string(sequence.begin(), sequence.end());
}

} // namespace null

BOOST_AUTO_TEST_SUITE(hmac)
BOOST_AUTO_TEST_CASE(create_hmac)
{
    try {

        secp::log(secp::INFO, "BOOST_AUTO_TEST_CASE(create_hmac) - starting...");

        auto smallKey   = convertSequence(secp::generateRandomSequence(secp::Random::SIZE_96_BITS));
        auto correctKey = convertSequence(secp::generateRandomSequence(secp::Random::SIZE_256_BITS));
        std::string largeKey{correctKey};
        largeKey.insert(largeKey.end(), smallKey.begin(), smallKey.end());

        std::string message;
        // Create random message
        for (unsigned i(0); i < 10000; ++ i) {
            std::vector<unsigned char> sequence = secp::generateRandomSequence(secp::Random::SIZE_256_BITS);
            message.insert(message.end(), sequence.begin(), sequence.end());
        }

        BOOST_CHECK_THROW(secp::generateHmac(smallKey, message), secp::CryptoError);
        BOOST_CHECK_THROW(secp::generateHmac(largeKey, message), secp::CryptoError);

        std::string hmac = secp::generateHmac(correctKey, message);
        std::stringstream ss;
        ss << "BOOST_AUTO_TEST_CASE(create_hmac) - Generated hmac: '"
           << bin2hex(hmac) << "'";
        secp::log(secp::INFO, ss.str());
        secp::log(secp::INFO, "BOOST_AUTO_TEST_CASE(create_hmac) - end.");

    } catch(std::exception& e) {
        std::cerr << "CAUGHT std::exception. " << e.what() << ". Shutting down..\n\n";
    }
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(random_sequence)
BOOST_AUTO_TEST_CASE(create_random_sequence)
{
    try {

        secp::log(secp::INFO, "BOOST_AUTO_TEST_CASE(create_random_sequence) - starting...");

        unsigned iterations(1000);
        
	    testRandomSequence(iterations, secp::Random::SIZE_96_BITS);
	    testRandomSequence(iterations, secp::Random::SIZE_128_BITS);
	    testRandomSequence(iterations, secp::Random::SIZE_256_BITS);

        secp::log(secp::INFO, "BOOST_AUTO_TEST_CASE(create_random_sequence) - end.");

    } catch(std::exception& e) {
        std::cerr << "CAUGHT std::exception. " << e.what() << ". Shutting down..\n\n";
    }
}
BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(aes_encrypt_2)
BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_2)
{
    try {

        secp::log(secp::INFO, "BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_2) - starting...");
        checkCrypto();

        secp::Demo2Tester demo2Tester;
        testGCMEncryption("AES256-GCM-1", 1201, demo2Tester);

        secp::log(secp::INFO, "BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_2) - end.");

    } catch(std::exception& e) {
        std::cerr << "CAUGHT std::exception. " << e.what() << ". Shutting down..\n\n";
    }
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(aes_encrypt_3)
BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_3)
{
    try {

        secp::log(secp::INFO, "BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_3) - starting...");

        secp::Demo3Tester demo3Tester;
        testGCMEncryption("AES256-GCM-1", 1201, demo3Tester);

        secp::log(secp::INFO, "BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_3) - end.");

    } catch(std::exception& e) {
        std::cerr << "CAUGHT std::exception. " << e.what() << ". Shutting down..\n\n";
    }
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(aes_encrypt_4)
BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_4)
{
    try {

        secp::log(secp::INFO, "BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_4) - starting...");

        secp::Demo4Tester demo4Tester;
        testGCMEncryption4("AES256-GCM-1", 1201, demo4Tester);

        secp::log(secp::INFO, "BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_4) - end.");

    } catch(std::exception& e) {
        std::cerr << "CAUGHT std::exception. " << e.what() << ". Shutting down..\n\n";
    }
}
BOOST_AUTO_TEST_SUITE_END()
