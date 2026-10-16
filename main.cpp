#include <generator.hpp>
#include <logger.hpp>
#include <config.hpp>
#include <matcher.hpp>

int main() {
    Logger& logger = Logger::getInstance();
    Config& config = Config::getInstance();

    if (!config.loadConfig("setup.conf")) {
        logger.log(ERROR, "Failed to load config file");
        return 1;
    }

    logger.setLogFlags(INFO | ERROR | OUTPUT | DEBUG);

    ModbusTrafficGenerator generator;
    PacketMatcher matcher;

    matcher.startCapture(config.at("localInt"), config.at("localAddr"), true);
    matcher.startCapture(config.at("remoteInt"), config.at("remoteAddr"), false);

    matcher.startStatsOutput();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    logger.log(DEBUG, "Initializing responder");
    generator.startResponder();
    logger.log(INFO, "Responder initialized");

    logger.log(DEBUG, "Initializing controller");
    generator.startController(config.at("remoteAddr"));

    logger.log(DEBUG, "Stopping responder");
    generator.stopResponder();
    logger.log(INFO, "Responder stopped");

    for (int i = 0; i < matcher.captureThreads.size(); i++) {
        matcher.captureThreads.at(i).join();
    }
}