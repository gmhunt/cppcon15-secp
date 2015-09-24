//
// Created by Gwendolyn Hunt on 9/24/15.
//

#include "Properties.hpp"

namespace secp
{

/**
 * Algorithms for adding, setting and getting proerties
 */
template<typename ValType, typename PropType, typename MapType>
PropType& addProperty(const std::string& name,
                      const ValType& defaultValue,
                      const std::string& description,
                      MapType& propertyMap,
                      ValuesMapType& valuesMap,
                      boost::program_options::options_description& optionsDescription)
{
    typedef typename MapType::value_type value_type;
    std::string defaultStringValue = boost::lexical_cast<std::string>(defaultValue);

    optionsDescription.add_options()
            (name.c_str(),boost::program_options::value<std::string>()->default_value(""), description.c_str());

    PropType newProperty(name, defaultValue, description);

    valuesMap.insert(ValuesMapType::value_type(name, defaultStringValue));
    propertyMap.insert(value_type(name, newProperty));
    return propertyMap[name];
}

template<typename ValType, typename MapType>
ValType getPropertyByType(const std::string& name, const MapType& propertyMap)
{
    ValType value;
    typedef typename MapType::const_iterator citerator_type;
    citerator_type citerator = propertyMap.find(name);
    if (citerator != propertyMap.end()) {
        value = citerator->second.value();
    } else {
        boost::format f(errorFormatNotFound);
        f % name;
        THROW_SECP_ERROR(PropertyNotFoundError, f.str());
    }
    return value;
}

template<typename ValType, typename MapType>
void setPropertyByType(const std::string& name, const ValType& value, MapType& propertyMap)
{
    typedef typename MapType::iterator iterator_type;
    iterator_type iterator = propertyMap.find(name);
    if (iterator != propertyMap.end()) {
        iterator->second.setValue(value);
    } else {
        boost::format f(errorFormatNotFound);
        f % name;
        THROW_SECP_ERROR(PropertyNotFoundError, f.str());
    }
}


Properties::Properties(const std::string& systemName, const std::string& systemVersion)
        : systemName_(systemName),
          systemVersion_(systemVersion)
{}

Properties::~Properties()
{}

Uint32Property& Properties::addUint32Property(const std::string& name,
                                              const boost::uint32_t& defaultValue,
                                              const std::string& description)
{
    return addProperty< boost::uint32_t, Uint32Property, Uint32PropMapType >(name,
           defaultValue, description, uint32PropertiesMap_, valuesMap_, description_);
}

/**
 * Property Accessors
 */
std::uint32_t Properties::getUint32(const std::string& name) const
{
    return getPropertyByType< std::uint32_t, Uint32PropMapType >(name, uint32PropertiesMap_);
}

/**
 * Property Mutators
 */
void Properties::setUint32(const std::string& name, const boost::uint32_t& value)
{
    setPropertyByType< boost::uint32_t, Uint32PropMapType >(name, value, uint32PropertiesMap_);
}

/**
 * Property Loaders
 */
void Properties::readCommandLine(int argc, char* argv[])
{
    boost::program_options::variables_map commandLineMap;

    try {

        parseCommandLine(argc, argv, commandLineMap);

        BOOST_FOREACH(ValuesMapType::value_type& pair, valuesMap_) {
            std::string key = pair.first;
            std::string commandLineValue;

            if (!commandLineMap[key].empty()) {
                commandLineValue = commandLineMap[key].as<std::string>();
                pair.second = commandLineValue;
            }
        }

        storeParsedValues();

    } catch (PropertiesError& /*e*/) {
        throw;
    } catch (std::exception& e) {
        std::stringstream ss;
        ss <<  "Properties::readCommandLine() - caught std::exception, error:" << e .what();
        THROW_SECP_ERROR(PropertiesError, ss.str().c_str());
    }
}

void Properties::printProperties()
{
    BOOST_FOREACH(const Uint32PropMapType::value_type& pair, uint32PropertiesMap_) {
        std::cout << pair.first << "=" << pair.second.stringValue() << std::endl;
    }
}

void Properties::checkCommandLineHelp(boost::program_options::variables_map& commandLineMap)
{
    if (commandLineMap.count("help")) {
//            printUsage();
        exit(EXIT_SUCCESS);
    } else if (commandLineMap.count("version")) {
//            printVersion();
        exit(EXIT_SUCCESS);
    }
}
void Properties::parseCommandLine(int argc, char* argv[], boost::program_options::variables_map& commandLineMap)
{
    boost::program_options::store(
            boost::program_options::command_line_parser(argc, argv).options(description_).run(), commandLineMap);
    boost::program_options::notify(commandLineMap);
    checkCommandLineHelp(commandLineMap);
}

void Properties::storeParsedValues()
{
    typedef typename std::map<std::string, std::string>::const_iterator citerator_type;

    BOOST_FOREACH(Uint32PropMapType::value_type& pair, uint32PropertiesMap_) {
        std::string name = pair.first;
        citerator_type citerator = valuesMap_.find(name);
        if (citerator != valuesMap_.end()) {
            std::string cmdValue =  citerator->second;
            std::cout << "cmdValue: " << cmdValue << std::endl;
            pair.second.setStringValue(cmdValue);
        }
    }
}


} // namespace secp
