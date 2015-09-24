//
// Created by Gwendolyn Hunt on 9/23/15.
//

#include <boost/program_options.hpp>
#include <boost/thread.hpp>

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
    int threadCount{3};

    // Declare the supported options.
    boost::program_options::options_description desc("Allowed options");
    desc.add_options()
            ("help", "produce help message")
            ("thread.count", boost::program_options::value<int>(), "set number of worker threads")
            ;

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
    boost::program_options::notify(vm);

    if (vm.count("help")) {
        std::cout << desc << "\n";
        return 1;
    }
    if (vm.count("thread.count")) {
        threadCount = vm["thread.count"].as<int>();
        std::cout << "thread.count was set to "
             << threadCount << ".\n";
    } else {
        std::cout << "Using default thread count " <<  threadCount << "\n";
    }

    Worker worker;
    boost::thread_group threadGroup;

    for (int i{0}; i < threadCount; ++i) {
        threadGroup.create_thread(boost::bind(&Worker::work, &worker));
    }
    threadGroup.join_all();

    return EXIT_SUCCESS;
}