#include <logger.hpp>

#include <iostream>
#include <chrono>
#include <iomanip>

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

Logger::Logger(): stopWorker(false), workerThread(std::thread(&Logger::processQueue, this)) {}

Logger::~Logger() {
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        stopWorker = true;
    }

    cv.notify_one();
    if (workerThread.joinable()) {
        workerThread.join();
    }
}

void Logger::log(LogLevel level, std::string message) {
    auto now = std::chrono::system_clock::now();
    std::time_t time_now = std::chrono::system_clock::to_time_t(now);

    LogEntry logEntry{time_now, level, message};

    {
        std::scoped_lock<std::mutex> lock(queueMutex);
        logQueue.push(logEntry);
    }

    cv.notify_one();
}

void Logger::processQueue() {
    while (true) {
            LogEntry logEntry;

            {
                std::unique_lock<std::mutex> lock(queueMutex);
                cv.wait(lock, [this]() {
                    return !logQueue.empty() || stopWorker;
                });

                if (stopWorker && logQueue.empty()) { break; }

                logEntry = logQueue.front();
                logQueue.pop();
            }

            std::ostringstream logString;

            logString << "[" << std::put_time(std::localtime(&logEntry.time), "%Y-%m-%d %H:%M:%S") << "] ";
            logString << levelToString(logEntry.level) << ": ";
            logString << logEntry.message << std::endl;

            std::cout << logString.str();
        }
}

std::string Logger::levelToString(LogLevel level) {
    switch (level) {
            case INFO: return "INFO";
            case DEBUG: return "DEBUG";
            case ERROR: return "ERROR";
            default: return "UNKNOWN";
    }
}