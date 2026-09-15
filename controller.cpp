#include <iostream>
#include <bitset>
#include <random>
#include <fcntl.h>
#include <thread>

#include <modbus/modbus-tcp.h>
#include <pcap/pcap.h>
#include <pcapplusplus/Packet.h>


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
        std::cerr << "Failed to create pcap handle for " << interface << ": " << errbuf << std::endl;
        return;
    }

    pcap_set_snaplen(handle, 65535);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 1000);

    int rc = pcap_activate(handle);
    if (rc < 0) {
        std::cerr << "Failed to activate pcap handle for " << handle << ": " << pcap_statustostr(rc);
        auto err = pcap_geterr(handle);
        if (err) std::cerr << " (" << err << ")";
        std::cerr << std::endl;

        pcap_close(handle);
        return;
    }

    bpf_program filter{};

    if (pcap_compile(handle, &filter, "port 502", 1, PCAP_NETMASK_UNKNOWN) < 0) {
        std::cerr << "Failed to compile packet filter" << std::endl;
        pcap_close(handle);
        return;
    }

    if (pcap_setfilter(handle, &filter) < 0) {
        std::cerr << "Failed to set packet filter" << std::endl;
        pcap_freecode(&filter);
        pcap_close(handle);
        return;
    }

    pcap_freecode(&filter);

    pcap_pkthdr* header = nullptr;
    const u_char* data = nullptr;

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
            std::cerr << "Packet capture error occured, exiting capture loop" << std::endl;
            break;
        } else {
            std::cerr << "Fatal packet capture error: " << pcap_geterr(handle) << std::endl;
        }
    }
}

void modbusResponder(modbus_t* ctx, int socket) {
    modbus_mapping_t* mapping = modbus_mapping_new(500, 500, 500, 500);

    while (true){
        int conn = modbus_tcp_accept(ctx, &socket);
        if (conn == -1) {
            std::cerr << "Connection failed" << std::endl;
        } else {
            std::cout << "Connection accepted" << std::endl;
        }

        while (true) {
            uint8_t* req = new uint8_t[MODBUS_TCP_MAX_ADU_LENGTH];
            int len = modbus_receive(ctx, req);
            if (len == -1) {
                std::cerr << "End of stream, closing connection" << std::endl;
                break;
            }
            
            modbus_reply(ctx, req, len, mapping);
        }
    }
}

void initResponder(std::string nsPath, std::string interface) {
    int fd = open(nsPath.c_str(), O_RDONLY);
    if (fd == -1) {
        std::cerr << "Failed to open netns descriptor" << std::endl;
        return;
    }

    if (setns(fd, CLONE_NEWNET) == -1) {
        std::cerr << "Failed to change netns" << std::endl;
        close(fd);
        return;
    }

    close(fd);

    modbus_t* ctx = modbus_new_tcp(NULL, 502);

    int socket = modbus_tcp_listen(ctx, 1);
    if (socket == -1) {
        std::cerr << "Failed to open socket: " << modbus_strerror(errno) << std::endl;
        return;
    }

    std::thread captureThread(capturePackets, interface);
    std::thread responderThread(modbusResponder, ctx, socket);

    captureThread.detach();
    responderThread.detach();
}

int main(int argc, char* argv[]) {
    std::thread initThread(initResponder, "/run/netns/ue", "wwp0s20f0u9i4");
    initThread.join();

    std::this_thread::sleep_for(std::chrono::seconds(3));

    std::thread captureThread(capturePackets, "ogstun");
    captureThread.detach();

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> rand_bit(0, 1);
    std::uniform_int_distribution<int> rand_addr(0, 435);

    modbus_t* ctx = modbus_new_tcp(argv[1], 502);

    if (modbus_connect(ctx) == 0) {
        std::cout << "Connection successful" << std::endl;
    } else {
        std::cout << "Connection failed: " << modbus_strerror(errno) << std::endl;
        return 1;
    }

    uint8_t* data = new uint8_t[64];

    for (int i = 0; i < 100; i++) {
        for (int j = 0; j < 64; j++) {
            data[j] = rand_bit(gen);
        }

        int sent = modbus_write_bits(ctx, rand_addr(gen), 64, data);
        if (sent == -1) {
            std::cerr << "Failed to send instructions" << std::endl;
        }
    }

    uint8_t* dest = new uint8_t;
    for (int i = 0; i < 500 ; i++) {
        int read = modbus_read_bits(ctx, i, 1, dest);
        if (read == -1) {
            std::cerr << "Failed to read reply" << std::endl;
        }
    }
    
    modbus_close(ctx);
    modbus_free(ctx);
}