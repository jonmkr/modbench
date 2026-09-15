#include <iostream>
#include <bitset>
#include <random>
#include <modbus/modbus-tcp.h>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>


void print_array(uint8_t arr[], int n) {
    for (int i = 0; i < n; i++) {
        std::cout << (int)arr[i];
    }
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    pcpp::PcapLiveDevice *dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName("ogstun");

    if (!dev->open()) {
        std::cerr << "Failed to open device for packet capture" << std::endl;
        return 1;
    }

    pcpp::PortFilter portFilter(502, pcpp::SRC_OR_DST);
    dev->setFilter(portFilter);

    pcpp::RawPacketVector packetVector;

    if (!dev->startCapture(packetVector)) {
        std::cerr << "Failed to start packet capture" << std::endl;
        dev->close();
        return 1;
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> rand_bit(0, 1);
    std::uniform_int_distribution<int> rand_addr(0, 435);

    modbus_t* ctx = modbus_new_tcp(argv[1], 502);

    if (modbus_connect(ctx) == 0) {
        std::cout << "Connection successful" << std::endl;
    } else {
        std::cout << "Connection failed" << std::endl;
        return 1;
    }

    uint8_t* data = new uint8_t[64];

    for (int i = 0; i < 100; i++) {
        for (int j = 0; j < 64; j++) {
            data[j] = rand_bit(gen);
        }

        print_array(data, 64);

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

    dev->stopCapture();

    pcpp::PcapNgFileWriterDevice writer("controller.pcapng");

    if (!writer.open()) {
            std::cerr << "Failed to open pcap writer" << std::endl;
            return 1;
        }

    if (!writer.writePackets(packetVector)) {
        std::cerr << "Failed to write packets to file" << std::endl;
        return 1;
    }

    writer.close();
    
    modbus_close(ctx);
    modbus_free(ctx);
}