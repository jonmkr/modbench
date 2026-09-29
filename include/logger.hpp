#include <chrono>
#include <string>

#include <mutex>
#include <condition_variable>
#include <queue>
#include <thread>

enum LogLevel {INFO, DEBUG, ERROR};

struct LogEntry {
    std::chrono::system_clock::time_point time;
    LogLevel level;
    std::string message;
};

class Logger {
public: 
    static Logger& getInstance();
    void log(LogLevel level, std::string message);

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

private:
    std::mutex queueMutex;
    std::condition_variable cv;
    std::queue<LogEntry> logQueue;
    std::thread workerThread;
    bool stopWorker;

    Logger();
    ~Logger();
    void processQueue();
    std::string levelToString(LogLevel);
};