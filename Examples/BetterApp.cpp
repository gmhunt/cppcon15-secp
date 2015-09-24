//
// Created by Gwendolyn Hunt on 9/23/15.
//

#include <boost/bind.hpp>
#include <boost/program_options.hpp>
#include <boost/foreach.hpp>
#include <boost/thread.hpp>
#include "Properties.hpp"

class Worker
{
public:
    void work()
    {
        /**
         * This is a crazy stupid buffer size but we are doing
         * it to consume resources for the demo
         */
        std::vector<char> buffer(1024*1024*24, 0);
        while (true) {
            boost::this_thread::sleep_for(boost::chrono::seconds(1));
        }
    }
};

int main(int argc, char *argv[])
{
    std::uint32_t threadCount{3};
    int rc(EXIT_SUCCESS);

    try {

        secp::Properties properties("ex4", "1.0.0");
        std::cout << "Starting..." << std::endl;

        properties.addUint32Property("thread.count", 3, "Number of worker threads").setRange(1, 5);
        properties.readCommandLine(argc, argv);
        threadCount = properties.getUint32("thread.count");
        properties.printProperties();

        Worker worker;
        boost::thread_group threadGroup;

        for (std::uint32_t i{0}; i < threadCount; ++i) {
            threadGroup.create_thread(boost::bind(&Worker::work, &worker));
        }
        threadGroup.join_all();

    } catch(const secp::PropertiesError& e) {
        std::cout << "Error: " << e.what() << std::endl;
        rc = EXIT_FAILURE;
    }

    return rc;
}