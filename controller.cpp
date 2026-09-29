#include <iostream>
#include <bitset>
#include <random>
#include <fcntl.h>
#include <thread>
#include <format>

#include <modbus/modbus-tcp.h>
#include <pcap/pcap.h>
#include <pcapplusplus/Packet.h>

#include <logger.hpp>


void print_array(uint8_t arr[], int n) {
    for (int i = 0; i < n; i++) {
        std::cout << (int)arr[i];
    }
    std::cout << std::endl;
}


void capturePackets(const std::string& interface) {
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

void modbusResponder(modbus_t* ctx, int socket) {
    modbus_mapping_t* mapping = modbus_mapping_new(500, 500, 500, 500);

    while (true){
        int conn = modbus_tcp_accept(ctx, &socket);
        if (conn == -1) {
            Logger::getInstance().log(ERROR, "Responder failed to accept connection");
        } else {
           Logger::getInstance().log(INFO, "Connection from controller accepted");
        }

        while (true) {
            uint8_t* req = new uint8_t[MODBUS_TCP_MAX_ADU_LENGTH];
            int len = modbus_receive(ctx, req);
            if (len == -1) {
                Logger::getInstance().log(ERROR, "End of stream, closing connection");
                break;
            }
            
            modbus_reply(ctx, req, len, mapping);
        }
    }
}

void initResponder(std::string nsPath, std::string interface) {
    int fd = open(nsPath.c_str(), O_RDONLY);
    if (fd == -1) {
        Logger::getInstance().log(ERROR, "Failed to open netns descriptor");
        return;
    }

    if (setns(fd, CLONE_NEWNET) == -1) {
        Logger::getInstance().log(ERROR, "Failed to change netns");
        close(fd);
        return;
    }

    close(fd);

    modbus_t* ctx = modbus_new_tcp(NULL, 502);

    int socket = modbus_tcp_listen(ctx, 1);
    if (socket == -1) {
        Logger::getInstance().log(ERROR, std::format("Failed to open socket: {}", modbus_strerror(errno)));
        return;
    }

    std::thread captureThread(capturePackets, interface);
    std::thread responderThread(modbusResponder, ctx, socket);

    captureThread.detach();
    responderThread.detach();
}

void modbusController(const char* addr) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> rand_bit(0, 1);
    std::uniform_int_distribution<int> rand_addr(0, 435);

    modbus_t* ctx = modbus_new_tcp(addr, 502);

    if (modbus_connect(ctx) == 0) {
        Logger::getInstance().log(INFO, "Controller connected successfully");
    } else {
        Logger::getInstance().log(ERROR, std::format("Controller failed to connect: {}", modbus_strerror(errno)));
        return;
    }

    uint8_t* data = new uint8_t[64];

    for (int i = 0; i < 100; i++) {
        for (int j = 0; j < 64; j++) {
            data[j] = rand_bit(gen);
        }

        int sent = modbus_write_bits(ctx, rand_addr(gen), 64, data);
        if (sent == -1) {
            Logger::getInstance().log(ERROR, "Failed to send instructions");
        }
    }

    uint8_t* dest = new uint8_t;
    for (int i = 0; i < 500 ; i++) {
        int read = modbus_read_bits(ctx, i, 1, dest);
        if (read == -1) {
            Logger::getInstance().log(ERROR, "Failed to read reply");
        }
    }
    
    modbus_close(ctx);
    modbus_free(ctx);
}

int main(int argc, char* argv[]) {
    Logger::getInstance().log(INFO, "Starting application");

    std::thread initThread(initResponder, "/run/netns/ue", "wwp0s20f0u9i4");
    initThread.join();

    std::thread captureThread(capturePackets, "ogstun");
    captureThread.detach();

    std::thread controllerThread(modbusController, argv[1]);
    controllerThread.join();
}