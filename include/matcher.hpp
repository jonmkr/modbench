#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <unordered_map>

using time_point = std::chrono::system_clock::time_point;

enum PacketState {
    SRC_OUT = 1, 
    DST_IN, 
    DST_OUT, 
    SRC_IN
};

struct PacketCheckpoints {
    uint8_t flags = 0x0000;
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