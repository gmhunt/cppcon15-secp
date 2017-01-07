#include "PropertyErrors.hpp"
namespace secp
{

PropertiesError::PropertiesError(const char* fileName, unsigned int lineNumber, const char* message)
    : whatString_(std::string(fileName) + ":" + std::to_string(lineNumber) + " error: " + std::string(message))
{}

PropertiesError::PropertiesError(const char* fileName, unsigned int lineNumber, const std::string& message)
    : whatString_(std::string(fileName) + ":" + std::to_string(lineNumber) + " error: " + std::string(message))
{}

PropertiesError::~PropertiesError() throw()
{}

const char* PropertiesError::what() const throw ()
{
    return whatString_.c_str();
}


PropertyNotFoundError::PropertyNotFoundError(const char* fileName, unsigned int lineNumber, const char* message)
    : secp::PropertiesError(fileName, lineNumber, message)
{}

PropertyNotFoundError::PropertyNotFoundError(const char* fileName, unsigned int lineNumber, const std::string& message)
    : secp::PropertiesError(fileName, lineNumber, message.c_str())
{}

PropertyRangeLimitError::PropertyRangeLimitError(const char* fileName, unsigned int lineNumber, const char* message)
    : secp::PropertiesError(fileName, lineNumber, message)
{}

PropertyRangeLimitError::PropertyRangeLimitError(const char* fileName, unsigned int lineNumber, const std::string& message)
    : secp::PropertiesError(fileName, lineNumber, message.c_str())
{}

InvalidByteSizeDescriptorError::InvalidByteSizeDescriptorError(const char* fileName, unsigned int lineNumber, const char* message)
        : secp::PropertiesError(fileName, lineNumber, message)
{}

InvalidByteSizeDescriptorError::InvalidByteSizeDescriptorError(const char* fileName, unsigned int lineNumber, const std::string& message)
        : secp::PropertiesError(fileName, lineNumber, message.c_str())
{}

} // namespace secp

