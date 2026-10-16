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
#include <generator.hpp>

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
            std::unique_lock<std::mutex> lock(transmissionMutex);
            if (!capturedTransmissions.contains(ctx.transId)) {
                capturedTransmissions.insert({ctx.transId, PacketCheckpoints{}});
            }

            PacketCheckpoints cp = capturedTransmissions.at(ctx.transId);

            if ((cp.flags & ctx.state) == ctx.state)
                Logger::getInstance().log(INFO, "Packet state {} already set for transmission {}", static_cast<int>(ctx.state), ctx.transId);

            cp.flags |= ctx.state;
            
            switch (ctx.state) {
                case SRC_OUT:
                cp.srcOut = ctx.timestamp;
                break;
                
                case DST_IN:
                cp.dstIn = ctx.timestamp;
                break;
                
                case DST_OUT:
                cp.dstOut = ctx.timestamp;
                break;
                
                case SRC_IN:
                cp.srcIn = ctx.timestamp;
                break;

                default:
                Logger::getInstance().log(ERROR, "Unknown packet state");
            }
            
            capturedTransmissions.at(ctx.transId) = cp;
        }
    }
}

void PacketMatcher::startStatsOutput() {
    outputThread = std::thread([this]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(2));

            std::vector<PacketCheckpoints> completed;
            {
                std::unique_lock<std::mutex> lock(transmissionMutex);

                for (auto it = capturedTransmissions.begin(); it != capturedTransmissions.end();) {
                    const auto cp = it->second;

                    if ((cp.flags & 0b1111) == 0b1111) {
                        completed.push_back(cp);
                        it = capturedTransmissions.erase(it);
                    } else {
                        it++;
                    }
                }

                Logger::getInstance().log(DEBUG, "Complete: {} Partial: {}", completed.size(), capturedTransmissions.size());
            }

            std::chrono::nanoseconds totDstIn{};
            std::chrono::nanoseconds totDstOut{};
            std::chrono::nanoseconds totSrcIn{};

            for (PacketCheckpoints cp: completed) {
                totDstIn += cp.dstIn - cp.srcOut;
                totDstOut += cp.dstOut - cp.dstIn;
                totSrcIn += cp.srcIn - cp.dstOut;
            }

            if (completed.empty()) { continue; }

            std::chrono::milliseconds avgDstIn = std::chrono::duration_cast<std::chrono::milliseconds>(totDstIn / completed.size());
            std::chrono::microseconds avgDstOut = std::chrono::duration_cast<std::chrono::microseconds>(totDstOut / completed.size());
            std::chrono::milliseconds avgSrcIn = std::chrono::duration_cast<std::chrono::milliseconds>(totSrcIn / completed.size());

            Logger::getInstance().log(OUTPUT, "({}) {} {} {}", completed.size(), avgDstIn, avgDstOut, avgSrcIn);
        }
    });
}

void PacketMatcher::startCapture(const std::string& interface, const std::string& addr, bool source) {
    captureThreads.emplace_back(&PacketMatcher::capturePackets, this, interface, addr, source);
}


void PacketMatcher::capturePackets(const std::string& interface, const std::string& addr, bool source) {
    if (!source) {
        switchNetns("/run/netns/ue");
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_create(interface.c_str(), errbuf);
    if (!handle) {
        Logger::getInstance().log(ERROR, "Failed to create pcap handle for {}: {}", interface, errbuf);
        return;
    }

    pcap_set_snaplen(handle, 65535);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 1000);

    int rc = pcap_activate(handle);
    if (rc < 0) {
        Logger::getInstance().log(ERROR, "Failed to activate pcap handle for {}: {}", interface, pcap_statustostr(rc));
        auto err = pcap_geterr(handle);
        if (err) Logger::getInstance().log(ERROR, err);

        pcap_close(handle);
        return;
    }

    bpf_program filter{};

    if (pcap_compile(handle, &filter, "tcp port 502", 1, PCAP_NETMASK_UNKNOWN) < 0) {
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

    Logger::getInstance().log(INFO, "Starting packet capture on {}", interface);

    while (true) {
        int rc = pcap_next_ex(handle, &header, &data);

        if (rc == 1) {
            timespec ts{header->ts.tv_sec, header->ts.tv_usec * 1000L};
            pcpp::RawPacket rawPacket{data, (int)header->caplen, ts, false, pcpp::LINKTYPE_RAW};
            pcpp::Packet parsedPacket(&rawPacket);
            
            std::optional<PacketState> state;
            pcpp::IPv4Layer* ipv4 = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

            if (!ipv4) {
                Logger::getInstance().log(ERROR, "Non-ipv4 packet received");
                continue;
            }

            if (ipv4->getSrcIPv4Address().toString() == addr) {
                state = source ? SRC_OUT : DST_OUT;
            } else if (ipv4->getDstIPv4Address().toString() == addr) {
                state = source ? SRC_IN : DST_IN;
            }

            if (!state.has_value()) {
                Logger::getInstance().log(ERROR, "Unable to determine packet state: [{}]", ipv4->toString());
                continue;
            }

            pcpp::ModbusLayer* modbus = nullptr;
            pcpp::TcpLayer* tcp = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
            
            if (tcp->getSrcPort() == 502 || tcp->getDstPort() == 502) {
                size_t payloadSize = tcp->getLayerPayloadSize();
                if (payloadSize) {
                    modbus = new pcpp::ModbusLayer(tcp->getLayerPayload(), payloadSize, tcp, &parsedPacket);
                }
            }

            if (!modbus) {
                Logger::getInstance().log(DEBUG, "[{}]", tcp->toString());
                continue;
            }

            int transId = modbus->getTransactionId();
            delete modbus;

            time_point timestamp(std::chrono::seconds(ts.tv_sec) + std::chrono::nanoseconds(ts.tv_nsec));

            {
                std::unique_lock<std::mutex> lock(packetMutex);
                packetQueue.push(PacketContext{state.value(), transId, timestamp});
                cv.notify_one();
            }

        } else if (rc == 0){
            continue;
        } else if (rc == PCAP_ERROR_BREAK) {
            Logger::getInstance().log(ERROR, "Error occured during packet capture, exiting capture loop");
            break;
        } else {
            Logger::getInstance().log(ERROR, "Fatal error during packet capture {}", pcap_geterr(handle));
        }
    }
}
