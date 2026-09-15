#include <iostream>
#include <modbus/modbus-tcp.h>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>

int main() {
    pcpp::PcapLiveDevice *dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName("wwp0s20f0u9i4");
    
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

    modbus_mapping_t* mapping = modbus_mapping_new(500, 500, 500, 500);
    modbus_t* ctx = modbus_new_tcp(nullptr, 502);

    int socket = modbus_tcp_listen(ctx, 1);
    if (socket == -1) {
        std::cerr << "Failed to open socket" << std::endl;
        return 1;
    }

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

        pcpp::PcapNgFileWriterDevice writer("responder.pcapng");

        if (!writer.open()) {
                std::cerr << "Failed to open pcap writer" << std::endl;
                return 1;
            }

        if (!writer.writePackets(packetVector)) {
            std::cerr << "Failed to write packets to file" << std::endl;
            return 1;
        }

        writer.close();
        packetVector.clear();

        std::cout << "Captured packets written to file" << std::endl;
    }

    close(socket);
    modbus_close(ctx);
    modbus_free(ctx);
}