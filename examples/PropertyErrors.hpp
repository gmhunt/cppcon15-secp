#ifndef PROPERTY_ERRORS_HPP_
#define PROPERTY_ERRORS_HPP_

#include <sstream>
#include <iostream>
#include <string>
#include <iomanip>
#include <vector>

namespace secp
{

/**
 * Base properties error.
 */
class PropertiesError : public std::exception {
public:
    PropertiesError(const char* fileName, unsigned int lineNumber, const char* message);

    PropertiesError(const char* fileName, unsigned int lineNumber, const std::string& message);

    virtual ~PropertiesError() throw();

    virtual const char* what() const throw ();

private:
    std::string whatString_;
};

/**
 * Thrown when an error occurs finding a property.
 */
class PropertyNotFoundError : public secp::PropertiesError {
public:
    PropertyNotFoundError(const char* fileName, unsigned int lineNumber, const char* message);

    PropertyNotFoundError(const char* fileName, unsigned int lineNumber, const std::string& message);
};

/**
 * Thrown when an error occurs finding a property.
 */
class PropertyRangeLimitError : public secp::PropertiesError {
public:
    PropertyRangeLimitError(const char* fileName, unsigned int lineNumber, const char* message);

    PropertyRangeLimitError(const char* fileName, unsigned int lineNumber, const std::string& message);
};

/**
 * Thrown when unable to parse a bytes descriptor.
 */
class InvalidByteSizeDescriptorError : public secp::PropertiesError {
public:
    InvalidByteSizeDescriptorError(const char* fileName, unsigned int lineNumber, const char* message);

    InvalidByteSizeDescriptorError(const char* fileName, unsigned int lineNumber, const std::string& message);
};



} // namespace secp


#define THROW_SECP_ERROR(error, message) throw (error(__FILE__, __LINE__, message))
#define THROW_SECP_ERROR_PROPERTIES_ERROR(message) throw (secp::PropertiesError(__FILE__, __LINE__, message))
#define THROW_SECP_ERROR_PROPERTY_NOT_FOUND_ERROR(message) throw (secp::PropertyNotFoundError(__FILE__, __LINE__, message))
#define THROW_SECP_ERROR_PROPERTY_RANGE_LIMIT_ERROR(message) throw (secp::PropertyRangeLimitError(__FILE__, __LINE__, message))

#endif /* PROPERTY_ERRORS_HPP_ */
