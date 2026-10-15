#include <chrono>
#include <string>

#include <mutex>
#include <condition_variable>
#include <queue>
#include <thread>

enum LogLevel : uint8_t {
    INFO = 1 << 0, 
    DEBUG = 1 << 1, 
    ERROR = 1 << 2,
    OUTPUT = 1 << 3
};

struct LogEntry {
    std::chrono::system_clock::time_point time;
    LogLevel level;
    std::string message;
};

class Logger {
public: 
    static Logger& getInstance();
    void setLogFlags(uint8_t logFlags);
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    template <typename... _Args>
    inline void log(LogLevel level, std::string_view fmt, _Args&&... args) {
        auto now = std::chrono::system_clock::now();
        std::string message = std::vformat(fmt, std::make_format_args(args...));
        LogEntry logEntry{now, level, message};

        {
            std::scoped_lock<std::mutex> lock(queueMutex);
            logQueue.push(logEntry);
        }

        cv.notify_one();
    }

private:
    std::mutex queueMutex;
    std::condition_variable cv;
    std::queue<LogEntry> logQueue;
    std::thread workerThread;
    bool stopWorker;

    static inline uint8_t logFlags;

    Logger();
    ~Logger();
    void processQueue();
    std::string levelToString(LogLevel);
};