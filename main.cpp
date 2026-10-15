#include <generator.hpp>
#include <logger.hpp>
#include <config.hpp>
#include <matcher.hpp>

int main() {
    Logger& logger = Logger::getInstance();
    Config& config = Config::getInstance();

    logger.setLogFlags(INFO | ERROR | OUTPUT | DEBUG);

    ModbusTrafficGenerator generator;
    PacketMatcher matcher;

    matcher.startCapture("ogstun", "10.45.0.1", true);
    matcher.startCapture("wwp0s20f0u9i4", "10.45.0.2", false);

    matcher.startStatsOutput();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    logger.log(DEBUG, "Initializing responder");
    generator.startResponder();
    logger.log(INFO, "Responder initialized");


    logger.log(DEBUG, "Initializing controller");
    generator.startController("10.45.0.2");

    logger.log(DEBUG, "Stopping responder");
    generator.stopResponder();
    logger.log(INFO, "Responder stopped");

    for (int i = 0; i < matcher.captureThreads.size(); i++) {
        matcher.captureThreads.at(i).join();
    }
}