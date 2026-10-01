#include <unordered_map>
#include <queue>
#include <chrono>

#include <mutex>
#include <condition_variable>
#include <thread>

#include <pcap/pcap.h>
#include <pcapplusplus/Packet.h>

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

void capturePackets(const std::string& interface, const std::string& addr) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_create(interface.c_str(), errbuf);
    if (!handle) {
        Logger::getInstance().log(ERROR, std::format("Failed to create pcap handle for {}: {}", interface, errbuf));
        return;
    }

    pcap_set_snaplen(handle, 65535);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 1000);

    int rc = pcap_activate(handle);
    if (rc < 0) {
        Logger::getInstance().log(ERROR, std::format("Failed to activate pcap handle for {}: {}", interface, pcap_statustostr(rc)));
        auto err = pcap_geterr(handle);
        if (err) Logger::getInstance().log(ERROR, err);

        pcap_close(handle);
        return;
    }

    bpf_program filter{};

    if (pcap_compile(handle, &filter, "port 502", 1, PCAP_NETMASK_UNKNOWN) < 0) {
        Logger::getInstance().log(ERROR, "Failed to compile packet filter");
        pcap_close(handle);
        return;
    }

    if (pcap_setfilter(handle, &filter) < 0) {
        Logger::getInstance().log(ERROR, "Failed to set packet filter");
        pcap_freecode(&filter);
        pcap_close(handle);
        return;
    }

    pcap_freecode(&filter);

    pcap_pkthdr* header = nullptr;
    const u_char* data = nullptr;

    Logger::getInstance().log(INFO, std::format("Starting packet capture on {}", interface));

    while (true) {
        int rc = pcap_next_ex(handle, &header, &data);

        if (rc == 1) {
            pcpp::RawPacket raw_packet {
                data, 
                header->caplen, 
                timeval{header->ts.tv_sec, header->ts.tv_usec}, 
                false};

        } else if (rc == 0){
            continue;
        } else if (rc == PCAP_ERROR_BREAK) {
            Logger::getInstance().log(ERROR, "Error occured during packet capture, exiting capture loop");
            break;
        } else {
            Logger::getInstance().log(ERROR, std::format("Fatal error during packet capture {}", pcap_geterr(handle)));
        }
    }
}
