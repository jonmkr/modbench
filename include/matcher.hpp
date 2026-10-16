#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <unordered_map>

using time_point = std::chrono::system_clock::time_point;

enum PacketState : uint8_t {
    SRC_OUT = 0b0001, 
    DST_IN = 0b0010, 
    DST_OUT = 0b0100, 
    SRC_IN = 0b1000
};

struct PacketCheckpoints {
    uint8_t flags = 0b0000;
    time_point srcOut;
    time_point dstIn;
    time_point dstOut;
    time_point srcIn;
};

struct PacketContext {
    PacketState state;
    int transId;
    time_point timestamp;
};

class PacketMatcher {
public:
    PacketMatcher();
    void startCapture(const std::string& interface, const std::string& addr, bool source);
    void startStatsOutput();
    
    std::vector<std::thread> captureThreads;

private:
    void processQueue();

    std::thread outputThread;

    std::queue<PacketContext> packetQueue;
    std::thread packetThread;
    std::mutex packetMutex;
    std::condition_variable cv;

    std::mutex transmissionMutex;
    std::unordered_map<int, PacketCheckpoints> capturedTransmissions;
    
    void capturePackets(const std::string& interface, const std::string& addr, bool source);
};