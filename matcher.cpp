#include <unordered_map>
#include <queue>
#include <chrono>

#include <mutex>
#include <condition_variable>
#include <thread>

#include <pcap/pcap.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/ModbusLayer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/IPv4Layer.h>

#include <logger.hpp>
#include <matcher.hpp>

PacketMatcher::PacketMatcher() : packetThread(std::thread(&PacketMatcher::processQueue, this)) {}


void PacketMatcher::processQueue() {
    while (true) {
        PacketContext ctx;
        {
            std::unique_lock<std::mutex> lock(packetMutex);
            cv.wait(lock);

            ctx = packetQueue.front();
            packetQueue.pop();
        }

        {
            std::scoped_lock<std::mutex> lock(transmissionMutex);
            if (!capturedTransmissions.contains(ctx.transId)) {
                capturedTransmissions.insert({ctx.transId, PacketCheckpoints{}});
            }

            switch (ctx.state) {
                case SRC_OUT:
                    capturedTransmissions.at(ctx.transId).srcOut = ctx.timestamp;
                    break;
                
                case DST_IN:
                    capturedTransmissions.at(ctx.transId).dstIn = ctx.timestamp;
                    break;
                
                case DST_OUT:
                    capturedTransmissions.at(ctx.transId).dstOut = ctx.timestamp;
                    break;
                
                case SRC_IN:
                    capturedTransmissions.at(ctx.transId).srcIn = ctx.timestamp;
            }
        }
    }
}

void PacketMatcher::startStatsOutput() {
    outputThread = std::thread([this]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            std::vector<PacketCheckpoints> completed;
            {
                std::scoped_lock<std::mutex> lock(transmissionMutex);
                
                for (auto it = capturedTransmissions.begin(); it != capturedTransmissions.end();) {
                    const auto& cp = it->second;
                
                    if (cp.srcIn != time_point()) {
                        completed.push_back(cp);
                        it = capturedTransmissions.erase(it);
                    } else {
                        it++;
                    }
                }
            }
            
            std::chrono::milliseconds tot_rtt{};
            for (PacketCheckpoints cp: completed) {
                tot_rtt += std::chrono::duration_cast<std::chrono::milliseconds>(cp.srcIn - cp.srcOut);
            }
 
            if (completed.empty()) { continue; }

            Logger::getInstance().log(OUTPUT, std::format("Tx/Avg {}/{}", completed.size(), tot_rtt / completed.size()));
        }
    });
}

void PacketMatcher::startCapture(const std::string& interface, const std::string& addr, bool source) {
    captureThreads.emplace_back(&PacketMatcher::capturePackets, this, interface, addr, source);
}


void PacketMatcher::capturePackets(const std::string& interface, const std::string& addr, bool source) {
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
            timespec ts{header->ts.tv_sec, header->ts.tv_usec * 1000L};
            pcpp::RawPacket rawPacket{data, (int)header->caplen, ts, false, pcpp::LINKTYPE_RAW};
            pcpp::Packet parsedPacket(&rawPacket);
            
            PacketState state;
            pcpp::IPv4Layer* ipv4 = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();


            if (ipv4->getSrcIPv4Address().toString() == addr) {
                state = source ? SRC_OUT : DST_IN;
            } else if (ipv4->getDstIPv4Address().toString() == addr) {
                state = source ? SRC_IN : DST_OUT;
            }

            Logger::getInstance().log(DEBUG, std::format("{} {} {} {}", addr, ipv4->getSrcIPAddress().toString(), ipv4->getDstIPAddress().toString(), static_cast<int>(state)));

            if (!state) {
                Logger::getInstance().log(ERROR, std::format("Failed to determine captured packet state: {} {}", addr, ipv4->toString()));
                continue;
            }

            pcpp::ModbusLayer* modbus;
            pcpp::TcpLayer* tcp = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
            
            Logger::getInstance().log(DEBUG, std::format("{}", tcp->toString()));

            if (tcp->getSrcPort() == 502 || tcp->getDstPort() == 502) {
                size_t payloadSize = tcp->getLayerPayloadSize();
                Logger::getInstance().log(DEBUG, std::format("TCP payload size: {}", payloadSize));
                if (payloadSize) {
                    modbus = new pcpp::ModbusLayer(tcp->getLayerPayload(), payloadSize, tcp, &parsedPacket);
                }
            }

            if (!modbus) {
                Logger::getInstance().log(ERROR, std::format("No Modbus payload in packet"));
                continue;
            }

            int transId = modbus->getTransactionId();
            Logger::getInstance().log(DEBUG, std::format("Transaction ID: {}", transId));

            time_point timestamp(std::chrono::seconds(ts.tv_sec) + std::chrono::nanoseconds(ts.tv_nsec));

            {
                std::scoped_lock<std::mutex> lock(packetMutex);
                packetQueue.push(PacketContext{state, transId, timestamp});
                cv.notify_one();
            }

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
