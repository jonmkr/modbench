#include <fcntl.h>
#include <bitset>
#include <random>

#include <modbus/modbus-tcp.h>

#include <generator.hpp>
#include <logger.hpp>

void switchNetns(std::string nsPath) {
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
}

ModbusTrafficGenerator::ModbusTrafficGenerator() {}

void ModbusTrafficGenerator::startResponder() {
    responderThread = std::thread(responderTask);
}

void ModbusTrafficGenerator::responderTask() {
    switchNetns("/run/netns/ue");

    modbus_mapping_t* mapping = modbus_mapping_new(500, 500, 500, 500);

    modbus_t* ctx = modbus_new_tcp(NULL, 502);

    int socket = modbus_tcp_listen(ctx, 1);
    if (socket == -1) {
        Logger::getInstance().log(ERROR, std::format("Failed to open socket: {}", modbus_strerror(errno)));
        return;
    }

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

void ModbusTrafficGenerator::controllerTask(const std::string& responderAddr) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> rand_bit(0, 1);
    std::uniform_int_distribution<int> rand_addr(0, 435);

    modbus_t* ctx = modbus_new_tcp(responderAddr.c_str(), 502);

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