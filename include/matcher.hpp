#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <unordered_map>

enum PacketState {SRC_OUT, DST_IN, DST_OUT, SRC_IN};

struct PacketCheckpoints {
    timeval srcOut;
    timeval dstIn;
    timeval dstOut;
    timeval srcIn;
};

struct PacketContext {
    PacketState state;
    int transId;
    timeval timestamp;
};

class PacketMatcher {
public:
    PacketMatcher();
    void enqueue(PacketState state, int transId, timeval timestamp);

private:
    void processQueue();
    void match(PacketContext context);

    std::thread workerThread;
    std::mutex queueMutex;
    std::condition_variable cv;
    std::queue<PacketContext> packetQueue;
    std::unordered_map<int, PacketCheckpoints> packetHash;

};