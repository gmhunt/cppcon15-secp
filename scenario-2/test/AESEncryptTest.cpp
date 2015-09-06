#include <boost/algorithm/hex.hpp>
#include "boost/format.hpp"
#include "boost/test/unit_test.hpp"

#include "TestCryptoController.hpp"
#include "CryptoError.hpp"
#include "RandomSequence.hpp"

#include "aesgcm256_1.hpp"
#include "aesgcm256_2.hpp"
#include "aesgcm256_3.hpp"
#include "aesgcm256_4.hpp"


#include <algorithm>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>

namespace
{

/**
 * The following classes the example encryp/decrypt functions
 * This allows us to test each variation using common test code.
 */
class TestWrapper
{
public:
    virtual void encrypt(const std::vector<unsigned char>& key,
                         const std::vector<unsigned char>& iv,
                         const std::vector<unsigned char>& plainText,
                         std::vector<unsigned char>& tag,
                         std::vector<unsigned char>& cipherText) = 0;

    virtual void decrypt(const std::vector<unsigned char>& key,
                         const std::vector<unsigned char>& tag,
                         const std::vector<unsigned char>& iv,
                         const std::vector<unsigned char>& cipherText,
                        std::vector<unsigned char>& plainText) = 0;
};

class Demo1Tester : public TestWrapper
{
public:
    void encrypt(const std::vector<unsigned char>& key,
                 const std::vector<unsigned char>& iv,
                 const std::vector<unsigned char>& plainText,
                 std::vector<unsigned char>& tag,
                 std::vector<unsigned char>& cipherText)
    {
        secp::authAes256GcmEncrypt_1(key, iv, plainText, tag, cipherText);
    }

    void decrypt(const std::vector<unsigned char>& key,
                 const std::vector<unsigned char>& tag,
                 const std::vector<unsigned char>& iv,
                 const std::vector<unsigned char>& cipherText,
                 std::vector<unsigned char>& plainText)
    {
        secp::authAes256GcmDecrypt_1(key, tag, iv, cipherText, plainText);
    };
};

class Demo2Tester : public TestWrapper
{
public:
    void encrypt(const std::vector<unsigned char>& key,
                 const std::vector<unsigned char>& iv,
                 const std::vector<unsigned char>& plainText,
                 std::vector<unsigned char>& tag,
                 std::vector<unsigned char>& cipherText)
    {
        secp::authAes256GcmEncrypt_2(key, iv, plainText, tag, cipherText);
    }

    void decrypt(const std::vector<unsigned char>& key,
                 const std::vector<unsigned char>& tag,
                 const std::vector<unsigned char>& iv,
                 const std::vector<unsigned char>& cipherText,
                 std::vector<unsigned char>& plainText)
    {
        secp::authAes256GcmDecrypt_2(key, tag, iv, cipherText, plainText);
    };
};

class Demo3Tester : public TestWrapper
{
public:
    void encrypt(const std::vector<unsigned char>& key,
                 const std::vector<unsigned char>& iv,
                 const std::vector<unsigned char>& plainText,
                 std::vector<unsigned char>& tag,
                 std::vector<unsigned char>& cipherText)
    {
        secp::authAes256GcmEncrypt_3(key, iv, plainText, tag, cipherText);
    }

    void decrypt(const std::vector<unsigned char>& key,
                 const std::vector<unsigned char>& tag,
                 const std::vector<unsigned char>& iv,
                 const std::vector<unsigned char>& cipherText,
                 std::vector<unsigned char>& plainText)
    {
        secp::authAes256GcmDecrypt_3(key, tag, iv, cipherText, plainText);
    };
};

class Demo4Tester : public TestWrapper
{
public:
    void encrypt(const std::vector<unsigned char>& key,
                 const std::vector<unsigned char>& iv,
                 const std::vector<unsigned char>& plainText,
                 std::vector<unsigned char>& tag,
                 std::vector<unsigned char>& cipherText)
    {
        secp::authAes256GcmEncrypt_4(key, iv, plainText, tag, cipherText);
    }

    void decrypt(const std::vector<unsigned char>& key,
                 const std::vector<unsigned char>& tag,
                 const std::vector<unsigned char>& iv,
                 const std::vector<unsigned char>& cipherText,
                 std::vector<unsigned char>& plainText)
    {
        secp::authAes256GcmDecrypt_4(key, tag, iv, cipherText, plainText);
    };
};

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
void testGCMEncryption(const std::string& testName, const unsigned iterations, TestWrapper& tester)
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

    std::stringstream ssA;
    ssA << "\n### AEAD TAG............size:[" << tag.length() << "], value: " << bin2hex(tag)
        << "\n### cipher text.........size:[" << cipherText.length() << "]";
    ssA << "\n### decrypt plain text..size:[" << decryptPlainText.length() << "]";
    logDebug(ssA.str());

    BOOST_CHECK(isEqualSequence(decryptPlainText, origPlainText));
}


} // namespace null

std::string bitsAsString(const secp::Random bits)
{
    std::string str;
    switch (bits) {
        case secp::Random::SIZE_96_BITS:
            str = "96";
            break;
        case secp::Random::SIZE_128_BITS:
            str = "128";
            break;
        case secp::Random::SIZE_256_BITS:
            str = "96";
            break;
        default:
            str = "Unknown";
            break;
    }
}

void testRandomSequence(const unsigned iterations, const secp::Random bits)
{
    std::string bitSize{bitsAsString(bits)};

    std::vector<std::string> vec;
    for (unsigned i(0); i < iterations; ++i) {
        std::vector<unsigned char> sequence{secp::generateRandomSequence(secp::Random::SIZE_256_BITS};
        vec.emplace_back(sequence.begin(), sequence.end());
        unsigned bitLen = sequence.size() * 8;
        BOOST_CHECK(bitLen == bits);
    }
    unsigned unique = removeDuplicates(vec);
    BOOST_CHECK(unique == iterations);
    if (unique == iterations) {
        logDebug(boost::str(boost::format("Successfully generated %1% unique %2%-bit sequences") % iterations % bitSize));
    } else {
        unsigned duplicates(iterations - unique);
        logDebug(boost::str(boost::format("Failure: Generated %1% duplicate %2%-bit sequences out of %3% iterations") %
                duplicates % bitSize % iterations));
    }
}

BOOST_AUTO_TEST_SUITE(random_sequence)
BOOST_AUTO_TEST_CASE(create_random_sequence)
{
    try {

        logInfo("BOOST_AUTO_TEST_CASE(create_random_sequence) - starting...");

        checkCrypto();

        unsigned iterations(1000);
	
    	std::vector<std::string> v256;
    	for (unsigned i(0); i < iterations; ++i) {
            std::vector<unsigned char> sequence{secp::generateRandomSequence(secp::Random::SIZE_256_BITS};
            v256.emplace_back(sequence.begin(), sequence.end());
            unsigned bitLen256key = aes256Key.length() * 8;
            BOOST_CHECK(bitLen256key == 256);
        }
    	unsigned unique256 = removeDuplicates(v256);
    	BOOST_CHECK(unique256 == iterations);
    	if (unique256 == iterations) {
    	    logDebug(boost::str(boost::format("Successfully generated %1% unique 256-bit sequences") % iterations));
        } else {
            unsigned duplicates(iterations - unique256);
            logDebug(boost::str(boost::format("Failure: Generated %1% duplicate 256-bit sequences out of %2% iterations") %
                    duplicates % iterations));
        }


        logInfo("BOOST_AUTO_TEST_CASE(create_random_sequence) - end.");

    } catch(std::exception& e) {
        std::cerr << "CAUGHT std::exception. " << e.what() << ". Shutting down..\n\n";
    }
}

BOOST_AUTO_TEST_CASE(create_aes_iv)
{
    try {

        logInfo("BOOST_AUTO_TEST_CASE(create_aes_iv) - starting...");

        checkCrypto();

        unsigned iterations(1000);

        std::vector<std::string> v96;
        for (unsigned i(0); i < iterations; ++i) {
            std::string aesGcmIV = cap::generateAesGcmIV();
            v96.push_back(aesGcmIV);
            unsigned bitLenGcmIV = aesGcmIV.length() * 8;
            BOOST_CHECK(bitLenGcmIV == 96);
        }
        unsigned unique96 = removeDuplicates(v96);
        BOOST_CHECK(unique96 == iterations);
        if (unique96 == iterations) {
            logDebug(boost::str(boost::format("Successfully generated %1% unique AES-GCM 96-bit iv") % iterations));
        } else {
            unsigned duplicates(iterations - unique96);
            logDebug(boost::str(boost::format("Generated %1% duplicate AES-GCM 128-bit IV out of %2% iterations") %
                    duplicates % iterations));
        }

        logInfo("BOOST_AUTO_TEST_CASE(create_aes_iv) - end.");

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
        Demo1Tester demo1Tester;
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
        Demo1Tester demo2Tester;
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
        Demo1Tester demo2Tester;
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
        Demo1Tester demo2Tester;
        testGCMEncryption("AES256-GCM-1", 1201, demo4Tester);

        logInfo("BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt_4) - end.");

    } catch(std::exception& e) {
        std::cerr << "CAUGHT std::exception. " << e.what() << ". Shutting down..\n\n";
    }
}
BOOST_AUTO_TEST_SUITE_END()BOOST_AUTO_TEST_SUITE_END()