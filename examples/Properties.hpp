//
// Created by Gwendolyn Hunt on 9/24/15.
//

#ifndef SECP_PROPERTIES_H
#define SECP_PROPERTIES_H

#include <boost/bind.hpp>
#include <boost/program_options.hpp>
#include <boost/foreach.hpp>
#include <boost/thread.hpp>
#include "PropertyTypes.hpp"
#include "PropertyErrors.hpp"

#include <cstdint>

namespace secp
{


typedef std::map<std::string, std::string> ValuesMapType;
typedef std::map<std::string, NumericProperty<std::uint32_t> > Uint32PropMapType;

/**
 * Quick hack for a properties object that forces range limits on uint32 properties.
 */
class Properties
{
public:
    Properties(const std::string& systemName, const std::string& systemVersion);

    virtual ~Properties();

    Uint32Property& addUint32Property(const std::string& name,
                                      const boost::uint32_t& defaultValue,
                                      const std::string& description);

    /**
     * Property Accessors
     */
    std::uint32_t getUint32(const std::string& name) const;

    /**
     * Property Mutators
     */
    void setUint32(const std::string& name, const boost::uint32_t& value);

    /**
     * Property Loaders
     */
    void readCommandLine(int argc, char* argv[]);

    void printProperties();

private:
    void checkCommandLineHelp(boost::program_options::variables_map& commandLineMap);

    void parseCommandLine(int argc, char* argv[], boost::program_options::variables_map& commandLineMap);

    void storeParsedValues();

    std::string systemName_;
    std::string systemVersion_;

    /**
     * Used to parse command line options and properties files.
    */
    boost::program_options::options_description description_;

    /**
     * Intermediate map used to store default values as strings of all properties
     * updated by parsing the container:
     *
     *      boost::program_options::options_description description_
     */
    std::map<std::string, std::string> valuesMap_;

    std::map<std::string, secp::NumericProperty<boost::uint32_t>> uint32PropertiesMap_;

};

} // namespace secp

#endif //SECP_PROPERTIES_H
