#include <unordered_map>
#include <queue>
#include <chrono>

#include <mutex>
#include <condition_variable>
#include <thread>

#include <logger.hpp>
#include <matcher.hpp>

PacketMatcher::PacketMatcher() : workerThread(std::thread(PacketMatcher::processQueue)) {}

void PacketMatcher::enqueue(PacketState state, int transId, timeval ts) {
    std::scoped_lock<std::mutex> lock(queueMutex);
    packetQueue.push(PacketContext{state, transId, ts});
    cv.notify_one();
}


void PacketMatcher::processQueue() {
    while (true) {
        PacketContext context;

        {
            std::unique_lock<std::mutex> lock(queueMutex);
            cv.wait(lock);

            context = packetQueue.front();
            packetQueue.pop();
        }

        match(context);
    }
}

void PacketMatcher::match(PacketContext ctx) {
    auto it = packetHash.end();

    switch (ctx.state) {
        case SRC_OUT:
            if (it = packetHash.find(ctx.transId); it == packetHash.end()) {
                Logger::getInstance().log(ERROR, "Duplicate packet captured at source egress");
                break;
            }

            PacketCheckpoints points;
            points.srcOut = ctx.timestamp;
            packetHash[ctx.transId] = points;
            break;
        
        case DST_IN:
            if (it = packetHash.find(ctx.transId); it != packetHash.end()) {
                Logger::getInstance().log(ERROR, "Missing packet reference at destination ingress");
                break;
            }

            it->second.dstIn = ctx.timestamp;
            break;

        case DST_OUT:
            if (auto it = packetHash.find(ctx.transId); it != packetHash.end()) {
                Logger::getInstance().log(ERROR, "Missing packet reference at destination egress");
                break;
            }

            it->second.dstOut = ctx.timestamp;
            break;
        
        case SRC_IN:
            if (auto it = packetHash.find(ctx.transId); it != packetHash.end()) {
                Logger::getInstance().log(ERROR, "Missing packet reference at source ingress");
                break;
            }

            it->second.srcIn = ctx.timestamp;
    }
}