#include <generator.hpp>
#include <logger.hpp>
#include <matcher.hpp>

int main() {
    Logger::getInstance().setLogFlags(INFO | ERROR | OUTPUT);

    ModbusTrafficGenerator generator;
    PacketMatcher matcher;

    matcher.startCapture("ogstun", "10.45.0.1", true);
    matcher.startStatsOutput();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    Logger::getInstance().log(DEBUG, "Initializing responder");
    generator.startResponder();
    Logger::getInstance().log(INFO, "Responder initialized");


    Logger::getInstance().log(DEBUG, "Initializing controller");
    generator.startController("10.45.0.2");

    Logger::getInstance().log(DEBUG, "Stopping responder");
    generator.stopResponder();
    Logger::getInstance().log(INFO, "Responder stopped");

    for (int i = 0; i < matcher.captureThreads.size(); i++) {
        matcher.captureThreads.at(i).join();
    }
}